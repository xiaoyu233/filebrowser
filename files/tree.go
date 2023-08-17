package files

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/spf13/afero"

	"github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/rules"
)

type TreeInfo struct {
	Path  string         `json:"path"`
	Name  string         `json:"name"`
	Files []TreeFileInfo `json:"files,omitempty"`
}

type TreeFileInfo struct {
	Fs        afero.Fs          `json:"-"`
	Path      string            `json:"path"`
	Name      string            `json:"name"`
	Size      int64             `json:"size"`
	ModTime   time.Time         `json:"modified"`
	IsSymlink bool              `json:"isSymlink"`
	Checksums map[string]string `json:"checksums,omitempty"`
}

type FileTreeOptions struct {
	Fs       afero.Fs
	Path     string
	Checker  rules.Checker
	Checksum string
}

func NewTreeInfo(opts FileTreeOptions) (*TreeInfo, error) {
	if !opts.Checker.Check(opts.Path) {
		return nil, os.ErrPermission
	}

	var tree *TreeInfo

	if lstaterFs, ok := opts.Fs.(afero.Lstater); ok {
		info, _, err := lstaterFs.LstatIfPossible(opts.Path)
		if err != nil {
			return nil, err
		}
		tree = &TreeInfo{
			Path: opts.Path,
			Name: info.Name(),
		}

		// 链接 or 单文件
		if IsSymlink(info.Mode()) || !info.IsDir() {
			return tree, nil
		}
	}

	// 遍历文件夹
	afero.Walk(opts.Fs, opts.Path, func(path string, info fs.FileInfo, err error) error {
		if path == opts.Path || info.IsDir() {
			return nil
		}

		// 链接 or 文件
		if tree.Files == nil {
			tree.Files = []TreeFileInfo{}
		}
		var file = TreeFileInfo{
			Fs:        opts.Fs,
			Path:      path,
			Name:      info.Name(),
			ModTime:   info.ModTime(),
			IsSymlink: IsSymlink(info.Mode()),
			Size:      info.Size(),
		}
		if !file.IsSymlink {
			file.Checksum(opts.Checksum)
		}
		tree.Files = append(tree.Files, file)
		return nil
	})

	return tree, nil
}

func (i *TreeFileInfo) Checksum(algo string) error {
	if i.Checksums == nil {
		i.Checksums = map[string]string{}
	}

	reader, err := i.Fs.Open(i.Path)
	if err != nil {
		return err
	}
	defer reader.Close()

	var h hash.Hash

	//nolint:gosec
	switch algo {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		return errors.ErrInvalidOption
	}

	_, err = io.Copy(h, reader)
	if err != nil {
		return err
	}

	i.Checksums[algo] = hex.EncodeToString(h.Sum(nil))
	return nil
}
