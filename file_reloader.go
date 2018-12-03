package main

import (
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// FileReloader used to reload certificate
type FileReloader struct {
	mutex       sync.RWMutex
	fileContent []byte
	filePath    string
}

// NewFileReloader new a keypair reloader
func NewFileReloader(filePath string, sig ...os.Signal) (*FileReloader, error) {
	reloader := &FileReloader{
		filePath: filePath,
	}

	// load first
	if err := reloader.maybeReload(); err != nil {
		return nil, err
	}

	// reload
	go func() {
		c := make(chan os.Signal, 1)
		if len(sig) == 0 {
			sig = []os.Signal{syscall.SIGUSR1}
		}
		signal.Notify(c, sig...)
		for s := range c {
			log.Printf("Received signal '%v', reloading file from '%s'\n", s, reloader.filePath)
			if err := reloader.maybeReload(); err != nil {
				log.Printf("Keeping old file content because new one could not be loaded: %v\n", err)
			}
		}
	}()

	return reloader, nil
}

// maybeReload used to reload keypair and swap into production
func (reloader *FileReloader) maybeReload() error {
	fileContent, err := ioutil.ReadFile(reloader.filePath)
	if err != nil {
		return err
	}
	reloader.SetFileContent(fileContent)
	return nil
}

// SetFileContent sets current file content
func (reloader *FileReloader) SetFileContent(fileContent []byte) {
	reloader.mutex.Lock()
	defer reloader.mutex.Unlock()
	reloader.fileContent = fileContent
}

// GetFileContentFunc returns function that returns content of filePath
func (reloader *FileReloader) GetFileContentFunc() func() []byte {
	return func() []byte {
		reloader.mutex.RLock()
		defer reloader.mutex.RUnlock()
		return reloader.fileContent
	}
}
