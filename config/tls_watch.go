package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// watch coalesces filesystem changes, including separate certificate/key writes.
// fsnotify uses inotify on Linux and native notifications on other platforms.
func (r *tlsCertificateReloader) watch() {
	defer close(r.done)
	defer func() { r.closeError = r.watcher.Close() }()

	const coalesceDelay = 100 * time.Millisecond
	var timer *time.Timer
	var pending <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	schedule := func() {
		// Bound the delay even if a watched directory has continuous activity.
		if pending == nil {
			if timer == nil {
				timer = time.NewTimer(coalesceDelay)
			} else {
				timer.Reset(coalesceDelay)
			}
			pending = timer.C
		}
	}

	for {
		select {
		case <-r.stop:
			return
		case event, ok := <-r.watcher.Events:
			if !ok {
				log.Print("TLS certificate watcher stopped; keeping the previous certificate")
				return
			}
			if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				// A watch follows an inode when a directory is moved. Drop that
				// watch so reconciliation can attach to the replacement directory.
				for _, dir := range r.watcher.WatchList() {
					if event.Name == dir {
						_ = r.watcher.Remove(dir)
					}
				}
			}
			schedule()
		case err, ok := <-r.watcher.Errors:
			if !ok {
				log.Print("TLS certificate watcher stopped; keeping the previous certificate")
				return
			}
			// In particular, rescan after queue overflow rather than relying on
			// a potentially lost write event to trigger the next reload.
			log.Printf("TLS certificate watcher error: %v", err)
			schedule()
		case <-pending:
			pending = nil
			previous := r.certificate.Load()
			err := r.watchDirectories()
			if err == nil {
				err = r.reload()
			}
			if err != nil {
				if message := err.Error(); message != r.lastError {
					log.Printf("TLS certificate reload failed; keeping the previous certificate: %s", message)
					r.lastError = message
				}
			} else {
				r.lastError = ""
				if r.certificate.Load() != previous {
					log.Print("Reloaded TLS certificate for HTTPS and gRPC")
				}
			}
			r.processed.Add(1)
		}
	}
}

// watchDirectories watches directories rather than certificate inodes so atomic
// file replacement works. Symlink parents catch link swaps (including Kubernetes
// ..data rotations); resolved target directories catch writes through links.
func (r *tlsCertificateReloader) watchDirectories() error {
	dirs := make(map[string]bool)
	seen := make(map[string]bool)
	var collect func(string) error
	addDirectory := func(dir string) error {
		// A temporarily missing directory can be recreated by a renewal tool.
		// Watch its nearest existing ancestor until reconciliation can descend.
		for {
			resolved, err := filepath.EvalSymlinks(dir)
			if err == nil {
				dirs[resolved] = true
				return nil
			}
			if !os.IsNotExist(err) || dir == filepath.Dir(dir) {
				return err
			}
			dir = filepath.Dir(dir)
		}
	}
	collect = func(path string) error {
		path, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if seen[path] {
			return nil
		}
		seen[path] = true
		if err := addDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		for component := path; ; component = filepath.Dir(component) {
			info, err := os.Lstat(component)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			if err == nil && info.Mode()&os.ModeSymlink != 0 {
				if err := addDirectory(filepath.Dir(component)); err != nil {
					return err
				}
				target, err := os.Readlink(component)
				if err != nil {
					return err
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(component), target)
				}
				if err := collect(target); err != nil {
					return err
				}
			}
			if component == filepath.Dir(component) {
				break
			}
		}
		return nil
	}
	for _, path := range []string{r.certFile, r.keyFile} {
		if err := collect(path); err != nil {
			return fmt.Errorf("resolving TLS certificate watch directories: %w", err)
		}
	}
	current := make(map[string]bool)
	for _, dir := range r.watcher.WatchList() {
		current[dir] = true
	}
	// Install new watches before removing stale targets to avoid gaps on rotation.
	for dir := range dirs {
		if !current[dir] {
			if err := r.watcher.Add(dir); err != nil {
				return fmt.Errorf("watching TLS certificate directory %q: %w", dir, err)
			}
		}
	}
	for dir := range current {
		if !dirs[dir] {
			_ = r.watcher.Remove(dir)
		}
	}
	return nil
}
