// FUSE filesystem implementation
use crate::config::{FileEntry, FileSource};
use crate::template::TemplateEngine;
use fuser::{
    FileAttr, FileType, Filesystem, INodeNo, MountOption, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEntry, ReplyOpen, Request,
};
use fuser::{FileHandle, FopenFlags, Generation, OpenFlags, WriteFlags};
use log::error;
use std::collections::HashMap;
use zeroize::Zeroize;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const CONTENT_TTL: Duration = Duration::from_secs(300);
const ATTR_TTL: Duration = Duration::from_secs(1);

// ─── Filesystem tree ──────────────────────────────────────────────────────────

enum FsNode {
    Dir {
        children: HashMap<String, u64>,
    },
    File {
        entry: FileEntry,
        cache: Mutex<Option<CachedContent>>,
    },
}

struct CachedContent {
    data: Vec<u8>,
    expires_at: std::time::Instant,
}

impl Drop for CachedContent {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

pub struct SecretFs {
    nodes: HashMap<u64, FsNode>,
    next_ino: u64,
    engine: Arc<TemplateEngine>,
}

impl SecretFs {
    pub fn new(files: HashMap<String, FileEntry>, engine: Arc<TemplateEngine>) -> Self {
        let mut fs = SecretFs {
            nodes: HashMap::new(),
            next_ino: 2,
            engine,
        };

        // Insert root directory (inode 1)
        fs.nodes.insert(
            1,
            FsNode::Dir {
                children: HashMap::new(),
            },
        );

        for (path, entry) in files {
            fs.insert_path(&path, entry);
        }

        fs
    }

    fn alloc_inode(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    fn insert_path(&mut self, path: &str, entry: FileEntry) {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return;
        }

        let mut parent_ino: u64 = 1;

        // Walk/create intermediate directories
        for component in &parts[..parts.len() - 1] {
            let component = component.to_string();
            let existing_ino = match self.nodes.get(&parent_ino) {
                Some(FsNode::Dir { children }) => children.get(&component).copied(),
                _ => None,
            };

            let dir_ino = if let Some(ino) = existing_ino {
                ino
            } else {
                let ino = self.alloc_inode();
                self.nodes.insert(ino, FsNode::Dir { children: HashMap::new() });
                if let Some(FsNode::Dir { children }) = self.nodes.get_mut(&parent_ino) {
                    children.insert(component, ino);
                }
                ino
            };

            parent_ino = dir_ino;
        }

        // Insert the file
        let file_name = parts[parts.len() - 1].to_string();
        let file_ino = self.alloc_inode();
        self.nodes.insert(
            file_ino,
            FsNode::File {
                entry,
                cache: Mutex::new(None),
            },
        );
        if let Some(FsNode::Dir { children }) = self.nodes.get_mut(&parent_ino) {
            children.insert(file_name, file_ino);
        }
    }

    /// Returns true if the inode is a directory.
    pub fn is_dir(&self, ino: u64) -> bool {
        matches!(self.nodes.get(&ino), Some(FsNode::Dir { .. }))
    }

    /// Look up a child inode by name in a parent directory.
    pub fn lookup_child(&self, parent: u64, name: &str) -> Option<u64> {
        match self.nodes.get(&parent)? {
            FsNode::Dir { children } => children.get(name).copied(),
            FsNode::File { .. } => None,
        }
    }

    /// List children of a directory as (name, inode) pairs.
    pub fn list_children(&self, ino: u64) -> Vec<(String, u64)> {
        match self.nodes.get(&ino) {
            Some(FsNode::Dir { children }) => {
                children.iter().map(|(k, v)| (k.clone(), *v)).collect()
            }
            _ => vec![],
        }
    }

    fn get_content(&self, ino: u64) -> Option<Vec<u8>> {
        let node = self.nodes.get(&ino)?;
        match node {
            FsNode::Dir { .. } => None,
            FsNode::File { entry, cache } => {
                {
                    let guard = cache.lock().unwrap();
                    if let Some(ref cached) = *guard {
                        if cached.expires_at > std::time::Instant::now() {
                            return Some(cached.data.clone());
                        }
                    }
                }

                let result = match &entry.source {
                    FileSource::Content(s) => Ok(s.clone()),
                    FileSource::Template(s) => self.engine.render_string(s).map_err(|e| e.to_string()),
                    FileSource::TemplateFile(path) => self.engine.render_file(path).map_err(|e| e.to_string()),
                    FileSource::Secret(uri) => self.engine.render_secret(uri).map_err(|e| e.to_string()),
                };

                match result {
                    Ok(content) => {
                        let data = content.into_bytes();
                        let mut guard = cache.lock().unwrap();
                        *guard = Some(CachedContent {
                            data: data.clone(),
                            expires_at: std::time::Instant::now() + CONTENT_TTL,
                        });
                        Some(data)
                    }
                    Err(e) => {
                        error!("failed to render content for inode {ino}: {e}");
                        None
                    }
                }
            }
        }
    }

    fn file_size(&self, ino: u64) -> u64 {
        self.get_content(ino).map(|d| d.len() as u64).unwrap_or(0)
    }

    fn now() -> SystemTime {
        SystemTime::now()
    }

    fn dir_attr(&self, ino: u64) -> FileAttr {
        let t = Self::now();
        FileAttr {
            ino: INodeNo(ino),
            size: 0,
            blocks: 0,
            atime: t,
            mtime: t,
            ctime: t,
            crtime: t,
            kind: FileType::Directory,
            perm: 0o555,
            nlink: 2,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn file_attr(&self, ino: u64) -> FileAttr {
        let t = Self::now();
        let size = self.file_size(ino);
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: (size + 511) / 512,
            atime: t,
            mtime: t,
            ctime: t,
            crtime: t,
            kind: FileType::RegularFile,
            perm: 0o444,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn get_attr(&self, ino: u64) -> Option<FileAttr> {
        match self.nodes.get(&ino)? {
            FsNode::Dir { .. } => Some(self.dir_attr(ino)),
            FsNode::File { .. } => Some(self.file_attr(ino)),
        }
    }
}

// ─── FUSE Filesystem trait ────────────────────────────────────────────────────

impl Filesystem for SecretFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::ENOENT);
                return;
            }
        };

        match self.lookup_child(parent.0, name_str) {
            Some(ino) => {
                if let Some(attr) = self.get_attr(ino) {
                    reply.entry(&ATTR_TTL, &attr, Generation(0));
                } else {
                    reply.error(fuser::Errno::ENOENT);
                }
            }
            None => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.get_attr(ino.0) {
            Some(attr) => reply.attr(&ATTR_TTL, &attr),
            None => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        reply.error(fuser::Errno::EACCES);
    }

    fn open(&self, _req: &Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        match self.get_content(ino.0) {
            Some(data) => {
                let start = (offset as usize).min(data.len());
                let end = (start + size as usize).min(data.len());
                reply.data(&data[start..end]);
            }
            None => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        _data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: fuser::ReplyWrite,
    ) {
        reply.error(fuser::Errno::EACCES);
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if !self.is_dir(ino.0) {
            reply.error(fuser::Errno::ENOTDIR);
            return;
        }

        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino.0, FileType::Directory, ".".to_string()),
            (ino.0, FileType::Directory, "..".to_string()),
        ];

        for (name, child_ino) in self.list_children(ino.0) {
            let kind = if self.is_dir(child_ino) {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            entries.push((child_ino, kind, name));
        }

        for (i, (child_ino, kind, name)) in entries.into_iter().enumerate() {
            if (i as u64) < offset {
                continue;
            }
            let full = reply.add(INodeNo(child_ino), (i + 1) as u64, kind, &name);
            if full {
                break;
            }
        }

        reply.ok();
    }
}

// ─── Mount helper ─────────────────────────────────────────────────────────────

pub fn mount(fs: SecretFs, mountpoint: &Path) -> std::io::Result<()> {
    let mut options = fuser::Config::default();
    options.mount_options = vec![
        MountOption::RO,
        MountOption::FSName("secret-fuse".to_string()),
    ];
    fuser::mount2(fs, mountpoint, &options)
}
