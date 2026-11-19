# -*- coding: utf-8 -*-
"""
Smart Scan File Dobel - versi PC (Windows)
Cari file dobel di satu drive penuh atau folder, cek, lalu bersihkan ke Recycle Bin.
"""
import os, sys, re, csv, time, string, shutil, hashlib, threading, queue, subprocess, ctypes
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from send2trash import send2trash
except Exception:
    send2trash = None
try:
    from PIL import Image, ImageTk
except Exception:
    Image = None

APP = "Smart Scan File Dobel"
IS_WIN = os.name == "nt"

CAT = {
    "Gambar": "jpg jpeg png gif webp bmp heic heif tif tiff svg raw cr2 nef arw dng psd ico avif",
    "Video": "mp4 mkv mov avi wmv flv webm m4v 3gp mts ts mpg mpeg",
    "Audio": "mp3 wav m4a aac flac ogg opus wma amr",
    "Dokumen": "pdf doc docx xls xlsx ppt pptx txt rtf odt ods odp csv md epub",
    "Arsip/Installer": "zip rar 7z tar gz bz2 xz iso apk exe msi",
}
EXT2CAT = {e: k for k, v in CAT.items() for e in v.split()}
SKIP_DIRS = {
    "windows", "program files", "program files (x86)", "programdata", "$recycle.bin",
    "system volume information", "recovery", "$windows.~bt", "$windows.~ws", "msocache",
    "appdata", "node_modules", ".git", "__pycache__", "_duplikat_smartscan", "config.msi",
    "perflogs", "windowsapps", "$sysreset", "onedrivetemp",
}
SKIP_FILES = {"pagefile.sys", "hiberfil.sys", "swapfile.sys", "thumbs.db", "desktop.ini", "dumpstack.log"}
COPY_RX = re.compile(r"(copy|salinan|duplikat|duplicate|\(\d+\)|-\s*copy)", re.I)
FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM = 0x2, 0x4
CLOUD_ONLY = 0x1000 | 0x400000 | 0x40000  # offline / recall-on-access (OneDrive dll. belum diunduh)


def fmt(b):
    b = float(b)
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024 or u == "TB":
            return f"{b:.0f} {u}" if u == "B" else f"{b:.2f} {u}" if b < 10 else f"{b:.1f} {u}"
        b /= 1024


def fdate(t):
    return time.strftime("%d-%m-%Y %H:%M", time.localtime(t))


def ext_of(p):
    return os.path.splitext(p)[1][1:].lower()


def norm_name(name):
    base, e = os.path.splitext(name.lower())
    base = re.sub(r"^(copy of|salinan dari|salinan)\s+", "", base)
    base = re.sub(r"\s*-\s*(copy|salinan)(\s*\(\d+\))?$", "", base)
    base = re.sub(r"\s*\((\d+|copy|salinan)\)$", "", base)
    base = re.sub(r"[\s_-]+(copy|salinan|duplikat|duplicate)\d*$", "", base)
    base = re.sub(r"[\s_.\-]+", " ", base).strip()
    return base + (".jpg" if e == ".jpeg" else e)


def list_drives():
    out = []
    if IS_WIN:
        for d in string.ascii_uppercase:
            root = f"{d}:\\"
            if os.path.exists(root):
                try:
                    u = shutil.disk_usage(root)
                    out.append((root, f"{root}  (terpakai {fmt(u.used)} dari {fmt(u.total)})"))
                except Exception:
                    out.append((root, root))
    else:
        out.append((os.path.expanduser("~"), os.path.expanduser("~")))
    return out


# ------------------------------------------------------------------ scanner
class Scanner(threading.Thread):
    def __init__(self, roots, cats, min_bytes, skip_sys, find_similar, q):
        super().__init__(daemon=True)
        self.roots, self.cats, self.min_bytes = roots, cats, min_bytes
        self.skip_sys, self.find_similar, self.q = skip_sys, find_similar, q
        self.stop = False

    def post(self, *a):
        self.q.put(a)

    def ok_file(self, name, size):
        if size < self.min_bytes or size == 0:
            return False
        if name.lower() in SKIP_FILES:
            return False
        cat = EXT2CAT.get(ext_of(name), "Lainnya")
        return cat in self.cats

    def walk(self):
        by_size, names = {}, []
        count, last = 0, 0
        seen_roots = set()
        for root in self.roots:
            stack = [root]
            while stack and not self.stop:
                d = stack.pop()
                key = os.path.normcase(os.path.abspath(d))
                if key in seen_roots:
                    continue
                seen_roots.add(key)
                try:
                    it = os.scandir(d)
                except Exception:
                    continue
                with it:
                    for e in it:
                        try:
                            if e.is_symlink():
                                continue
                            if self.skip_sys:
                                if e.name.startswith((".", "~$")):
                                    continue
                                if IS_WIN:
                                    attrs = getattr(e.stat(follow_symlinks=False), "st_file_attributes", 0)
                                    if attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM):
                                        continue
                            if e.is_dir(follow_symlinks=False):
                                if self.skip_sys and e.name.lower() in SKIP_DIRS:
                                    continue
                                stack.append(e.path)
                            elif e.is_file(follow_symlinks=False):
                                st = e.stat(follow_symlinks=False)
                                if getattr(st, "st_file_attributes", 0) & CLOUD_ONLY:
                                    continue  # jangan memicu unduhan file cloud
                                if not self.ok_file(e.name, st.st_size):
                                    continue
                                rec = (e.path, st.st_size, st.st_mtime)
                                by_size.setdefault(st.st_size, []).append(rec)
                                if self.find_similar and COPY_RX.search(e.name):
                                    names.append(rec)
                                count += 1
                        except Exception:
                            continue
                now = time.time()
                if now - last > 0.15:
                    last = now
                    self.post("status", f"Membaca daftar file… {count:,} file  |  {d}", None)
        return by_size, names, count

    def partial(self, path, size):
        h = hashlib.blake2b(digest_size=20)
        with open(path, "rb") as f:
            if size <= 256 * 1024:
                h.update(f.read())
                return "F" + h.hexdigest()
            h.update(f.read(65536))
            f.seek(size // 2)
            h.update(f.read(8192))
            f.seek(size - 65536)
            h.update(f.read(65536))
        return "Q" + h.hexdigest()

    def full(self, path, cb):
        h = hashlib.blake2b(digest_size=32)
        with open(path, "rb") as f:
            while True:
                if self.stop:
                    raise InterruptedError
                b = f.read(4 * 1024 * 1024)
                if not b:
                    break
                h.update(b)
                cb(len(b))
        return h.hexdigest()

    def run(self):
        t0 = time.time()
        try:
            by_size, copy_named, total = self.walk()
            cand = [r for v in by_size.values() if len(v) > 1 for r in v]
            self.post("status", f"{total:,} file ditemukan. Cek cepat {len(cand):,} kandidat…", 0.05)

            byq = {}
            for i, r in enumerate(cand):
                if self.stop:
                    break
                try:
                    byq.setdefault((r[1], self.partial(r[0], r[1])), []).append(r)
                except Exception:
                    pass
                if i % 25 == 0:
                    self.post("status", f"Cek cepat {i:,}/{len(cand):,}  |  {r[0]}", 0.05 + 0.35 * i / max(1, len(cand)))

            groups, need = [], []
            for (size, q), v in byq.items():
                if len(v) < 2:
                    continue
                (groups if q.startswith("F") else need).append(v)

            total_b = sum(r[1] for v in need for r in v) or 1
            done = [0]
            last = [0]

            def cb(n):
                done[0] += n
                now = time.time()
                if now - last[0] > 0.15:
                    last[0] = now
                    self.post("status", None, 0.4 + 0.6 * done[0] / total_b)

            try:
                for v in need:
                    byf = {}
                    for r in v:
                        self.post("status", f"Verifikasi isi ({fmt(done[0])} / {fmt(total_b)})  |  {r[0]}", None)
                        try:
                            byf.setdefault(self.full(r[0], cb), []).append(r)
                        except InterruptedError:
                            raise
                        except Exception:
                            pass
                    groups += [g for g in byf.values() if len(g) > 1]
            except InterruptedError:
                pass

            exact_paths = {r[0] for g in groups for r in g}
            similar = []
            if self.find_similar:
                # file bertanda copy/(1) dicocokkan dengan file "asli" bernama sama di folder yang sama/lain
                index = {}
                for v in by_size.values():
                    for r in v:
                        if r[0] in exact_paths:
                            continue
                        index.setdefault(norm_name(os.path.basename(r[0])), []).append(r)
                seen = set()
                for r in copy_named:
                    k = norm_name(os.path.basename(r[0]))
                    if k in seen or r[0] in exact_paths:
                        continue
                    seen.add(k)
                    g = index.get(k, [])
                    if 1 < len(g) <= 50:
                        similar.append(g)
            self.post("done", groups, similar, total, time.time() - t0)
        except Exception as ex:
            self.post("error", str(ex))


# ------------------------------------------------------------------ GUI
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP)
        self.geometry("1280x800")
        self.minsize(1000, 640)
        self.q = queue.Queue()
        self.scanner = None
        self.exact, self.similar = [], []      # list of groups; group = list of dict
        self.iidmap = {}                       # iid -> (group, file dict)
        self.preview_img = None
        self.style()
        self.build()
        self.after(100, self.poll)

    # ---------- look
    def style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except Exception:
            pass
        bg, card = "#f6f4ef", "#ffffff"
        self.configure(bg=bg)
        base = ("Segoe UI", 10)
        s.configure(".", font=base, background=bg)
        s.configure("Card.TFrame", background=card)
        s.configure("Card.TLabel", background=card)
        s.configure("Card.TCheckbutton", background=card)
        s.configure("H.TLabel", font=("Segoe UI Semibold", 16), background=bg)
        s.configure("Sub.TLabel", foreground="#6b7280", background=bg)
        s.configure("Stat.TLabel", font=("Segoe UI Semibold", 12), background=bg)
        s.configure("Accent.TButton", background="#e8a317", foreground="#2b1d00", font=("Segoe UI Semibold", 10), padding=(14, 7))
        s.map("Accent.TButton", background=[("active", "#d6950f"), ("disabled", "#e6dcc4")])
        s.configure("Danger.TButton", background="#c2410c", foreground="#ffffff", font=("Segoe UI Semibold", 10), padding=(12, 6))
        s.map("Danger.TButton", background=[("active", "#a3370a"), ("disabled", "#e3c3b6")])
        s.configure("TButton", padding=(10, 5))
        s.configure("Treeview", rowheight=26, font=base)
        s.configure("Treeview.Heading", font=("Segoe UI Semibold", 10))
        s.configure("TProgressbar", troughcolor="#e6e2d8", background="#e8a317", thickness=10)

    # ---------- layout
    def build(self):
        top = ttk.Frame(self, padding=(16, 12, 16, 4))
        top.pack(fill="x")
        ttk.Label(top, text="🗂  " + APP, style="H.TLabel").pack(anchor="w")
        ttk.Label(top, text="Pilih drive atau folder → Mulai Scan → cek hasil → pindahkan salinan ke Recycle Bin.",
                  style="Sub.TLabel").pack(anchor="w")

        box = ttk.Frame(self, style="Card.TFrame", padding=12)
        box.pack(fill="x", padx=16, pady=6)

        # lokasi
        loc = ttk.Frame(box, style="Card.TFrame")
        loc.pack(fill="x")
        ttk.Label(loc, text="Lokasi:", style="Card.TLabel", font=("Segoe UI Semibold", 10)).pack(side="left", padx=(0, 8))
        self.locframe = ttk.Frame(loc, style="Card.TFrame")
        self.locframe.pack(side="left", fill="x", expand=True)
        self.locvars = []
        for path, label in list_drives():
            self.add_loc(path, label, checked=False)
        ttk.Button(loc, text="＋ Tambah folder", command=self.pick_folder).pack(side="right")

        # opsi
        opt = ttk.Frame(box, style="Card.TFrame")
        opt.pack(fill="x", pady=(10, 0))
        ttk.Label(opt, text="Jenis:", style="Card.TLabel").pack(side="left")
        self.catvars = {}
        for c in list(CAT) + ["Lainnya"]:
            v = tk.BooleanVar(value=c != "Lainnya")
            self.catvars[c] = v
            ttk.Checkbutton(opt, text=c, variable=v, style="Card.TCheckbutton").pack(side="left", padx=4)
        ttk.Label(opt, text="   Abaikan file di bawah", style="Card.TLabel").pack(side="left")
        self.minkb = tk.StringVar(value="50")
        ttk.Spinbox(opt, from_=0, to=10_000_000, textvariable=self.minkb, width=7).pack(side="left", padx=4)
        ttk.Label(opt, text="KB", style="Card.TLabel").pack(side="left")
        self.skipsys = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="Lewati folder sistem & tersembunyi", variable=self.skipsys,
                        style="Card.TCheckbutton").pack(side="left", padx=(14, 4))
        self.dosim = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text='Cari nama mirip ("copy", "(1)")', variable=self.dosim,
                        style="Card.TCheckbutton").pack(side="left", padx=4)

        # tombol + progress
        run = ttk.Frame(box, style="Card.TFrame")
        run.pack(fill="x", pady=(12, 0))
        self.btn_scan = ttk.Button(run, text="▶  Mulai Scan", style="Accent.TButton", command=self.start)
        self.btn_scan.pack(side="left")
        self.btn_stop = ttk.Button(run, text="■ Berhenti", command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=8)
        self.pbar = ttk.Progressbar(run, mode="determinate", maximum=1000)
        self.pbar.pack(side="left", fill="x", expand=True, padx=8)
        self.status = tk.StringVar(value="Centang drive (misal D:\\) atau tambah folder, lalu klik Mulai Scan.")
        ttk.Label(box, textvariable=self.status, style="Card.TLabel", foreground="#6b7280").pack(fill="x", pady=(6, 0))

        # ringkasan
        self.summary = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.summary, style="Stat.TLabel", padding=(16, 4)).pack(fill="x")

        # toolbar hasil
        tb = ttk.Frame(self, padding=(16, 2))
        tb.pack(fill="x")
        ttk.Label(tb, text="Pilih otomatis, simpan:").pack(side="left")
        self.strategy = ttk.Combobox(tb, state="readonly", width=34, values=[
            "yang paling lama (biasanya asli)", "yang paling baru",
            "path paling pendek", 'nama paling bersih (tanpa "copy"/"(1)")'])
        self.strategy.current(0)
        self.strategy.pack(side="left", padx=6)
        ttk.Button(tb, text="Terapkan", command=lambda: self.apply_strategy(True)).pack(side="left")
        ttk.Button(tb, text="Simpan semua (batal pilih)", command=self.keep_all).pack(side="left", padx=6)
        ttk.Label(tb, text="   Cari:").pack(side="left")
        self.filter = tk.StringVar()
        e = ttk.Entry(tb, textvariable=self.filter, width=24)
        e.pack(side="left", padx=4)
        e.bind("<KeyRelease>", lambda ev: self.after_idle(self.refresh))
        self.btn_del = ttk.Button(tb, text="🗑  Pindahkan ke Recycle Bin", style="Danger.TButton",
                                  command=self.delete_selected, state="disabled")
        self.btn_del.pack(side="right")
        ttk.Button(tb, text="⬇ Ekspor CSV", command=self.export_csv).pack(side="right", padx=6)
        self.selinfo = tk.StringVar(value="")
        ttk.Label(tb, textvariable=self.selinfo).pack(side="right", padx=8)

        # area hasil
        pan = ttk.PanedWindow(self, orient="horizontal")
        pan.pack(fill="both", expand=True, padx=16, pady=(6, 14))
        left = ttk.Frame(pan)
        pan.add(left, weight=4)
        self.nb = ttk.Notebook(left)
        self.nb.pack(fill="both", expand=True)
        self.tree_exact = self.make_tree(self.nb)
        self.tree_sim = self.make_tree(self.nb)
        self.nb.add(self.tree_exact.master, text="  Isi sama persis  ")
        self.nb.add(self.tree_sim.master, text="  Nama mirip (cek manual)  ")
        ttk.Label(left, foreground="#6b7280",
                  text="Klik kolom Status atau tekan Spasi = ganti Simpan/Hapus  •  Klik dua kali = buka file  •  Klik kanan = menu").pack(anchor="w", pady=(4, 0))

        right = ttk.Frame(pan, style="Card.TFrame", padding=12, width=320)
        pan.add(right, weight=1)
        ttk.Label(right, text="Pratinjau", style="Card.TLabel", font=("Segoe UI Semibold", 11)).pack(anchor="w")
        self.pv = tk.Label(right, bg="#f1eee6", width=40, height=14, text="Pilih file untuk melihat", fg="#6b7280")
        self.pv.pack(fill="x", pady=8)
        self.pvinfo = tk.Text(right, height=9, wrap="word", relief="flat", bg="#ffffff", font=("Segoe UI", 9))
        self.pvinfo.pack(fill="both", expand=True)
        b = ttk.Frame(right, style="Card.TFrame")
        b.pack(fill="x", pady=(8, 0))
        ttk.Button(b, text="Buka file", command=self.open_file).pack(side="left")
        ttk.Button(b, text="Buka lokasi", command=self.open_loc).pack(side="left", padx=6)
        ttk.Button(b, text="Simpan/Hapus", command=self.toggle_current).pack(side="left")

        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Buka file", command=self.open_file)
        self.menu.add_command(label="Buka lokasi di Explorer", command=self.open_loc)
        self.menu.add_separator()
        self.menu.add_command(label="Tandai SIMPAN / HAPUS", command=self.toggle_current)
        self.menu.add_command(label="Simpan hanya file ini di grupnya", command=self.keep_only_this)
        self.menu.add_command(label="Simpan semua di grup ini", command=self.keep_group)

    def make_tree(self, parent):
        fr = ttk.Frame(parent)
        cols = ("status", "ukuran", "tanggal", "folder")
        t = ttk.Treeview(fr, columns=cols, selectmode="browse")
        t.heading("#0", text="Nama file / grup")
        t.heading("status", text="Status")
        t.heading("ukuran", text="Ukuran")
        t.heading("tanggal", text="Diubah")
        t.heading("folder", text="Folder")
        t.column("#0", width=300)
        t.column("status", width=90, anchor="center")
        t.column("ukuran", width=95, anchor="e")
        t.column("tanggal", width=125, anchor="center")
        t.column("folder", width=420)
        t.tag_configure("grp", background="#f1eee6", font=("Segoe UI Semibold", 10))
        t.tag_configure("keep", foreground="#1f8a5b")
        t.tag_configure("del", foreground="#c2410c")
        t.tag_configure("chk", foreground="#2563eb")
        sb = ttk.Scrollbar(fr, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        t.bind("<<TreeviewSelect>>", lambda e: self.show_preview())
        t.bind("<Double-1>", self.on_double)
        t.bind("<Button-1>", self.on_click)
        t.bind("<space>", lambda e: (self.toggle_current(), "break")[1])
        t.bind("<Button-3>", self.on_right)
        return t

    def add_loc(self, path, label, checked=True):
        v = tk.BooleanVar(value=checked)
        self.locvars.append((path, v))
        ttk.Checkbutton(self.locframe, text=label, variable=v, style="Card.TCheckbutton").pack(side="left", padx=4)

    def pick_folder(self):
        d = filedialog.askdirectory(title="Pilih folder untuk dipindai")
        if d:
            self.add_loc(os.path.normpath(d), os.path.normpath(d), True)

    # ---------- scan
    def start(self):
        roots = [p for p, v in self.locvars if v.get()]
        if not roots:
            messagebox.showinfo(APP, "Centang minimal satu drive atau folder dulu.")
            return
        cats = {c for c, v in self.catvars.items() if v.get()}
        if not cats:
            messagebox.showinfo(APP, "Pilih minimal satu jenis file.")
            return
        try:
            mb = int(float(self.minkb.get() or 0) * 1024)
        except ValueError:
            mb = 0
        self.clear_trees()
        self.summary.set("")
        self.pbar["value"] = 0
        self.btn_scan["state"] = "disabled"
        self.btn_stop["state"] = "normal"
        self.btn_del["state"] = "disabled"
        self.scanner = Scanner(roots, cats, mb, self.skipsys.get(), self.dosim.get(), self.q)
        self.scanner.start()

    def stop(self):
        if self.scanner:
            self.scanner.stop = True
            self.status.set("Menghentikan… hasil sejauh ini akan ditampilkan.")

    def poll(self):
        try:
            while True:
                m = self.q.get_nowait()
                if m[0] == "status":
                    if m[1]:
                        self.status.set(m[1][:220])
                    if m[2] is not None:
                        self.pbar["value"] = m[2] * 1000
                elif m[0] == "done":
                    self.on_done(*m[1:])
                elif m[0] == "error":
                    self.btn_scan["state"] = "normal"
                    self.btn_stop["state"] = "disabled"
                    messagebox.showerror(APP, "Terjadi kesalahan:\n" + m[1])
                elif m[0] == "deldone":
                    self.after_delete(*m[1:])
        except queue.Empty:
            pass
        self.after(100, self.poll)

    def on_done(self, groups, similar, total, secs):
        mk = lambda g: [{"path": p, "size": s, "mtime": t, "del": False} for p, s, t in g]
        self.exact = [mk(g) for g in groups]
        self.similar = [mk(g) for g in similar]
        self.total = total
        self.pbar["value"] = 1000
        self.btn_scan["state"] = "normal"
        self.btn_stop["state"] = "disabled"
        stopped = " (dihentikan)" if self.scanner.stop else ""
        self.status.set(f"Selesai dalam {secs:.0f} detik{stopped}. {total:,} file dipindai.")
        self.apply_strategy(False)
        self.refresh()
        if not self.exact:
            messagebox.showinfo(APP, "Bersih! Tidak ada file dengan isi sama persis.")

    # ---------- selection logic
    def apply_strategy(self, refresh=True):
        i = self.strategy.current()
        for g in self.exact:
            if i == 0:
                keep = min(g, key=lambda f: (f["mtime"], len(f["path"])))
            elif i == 1:
                keep = max(g, key=lambda f: f["mtime"])
            elif i == 2:
                keep = min(g, key=lambda f: len(f["path"]))
            else:
                keep = min(g, key=lambda f: (bool(COPY_RX.search(os.path.basename(f["path"]))),
                                             len(os.path.basename(f["path"])), f["mtime"]))
            for f in g:
                f["del"] = f is not keep
        if refresh:
            self.refresh()

    def keep_all(self):
        for g in self.exact + self.similar:
            for f in g:
                f["del"] = False
        self.refresh()

    def current(self):
        t = self.tree_exact if self.nb.index("current") == 0 else self.tree_sim
        sel = t.selection()
        return (t, sel[0]) if sel else (t, None)

    def toggle(self, iid):
        if iid not in self.iidmap:
            return
        g, f = self.iidmap[iid]
        if not f["del"] and sum(1 for x in g if not x["del"]) <= 1:
            self.status.set("Minimal satu file di setiap grup harus disimpan.")
            self.bell()
            return
        f["del"] = not f["del"]
        self.update_row(iid)
        self.update_selinfo()

    def toggle_current(self):
        t, iid = self.current()
        if iid:
            self.toggle(iid)

    def keep_only_this(self):
        t, iid = self.current()
        if iid in self.iidmap:
            g, f = self.iidmap[iid]
            for x in g:
                x["del"] = x is not f
            self.refresh()

    def keep_group(self):
        t, iid = self.current()
        if iid in self.iidmap:
            for x in self.iidmap[iid][0]:
                x["del"] = False
            self.refresh()

    # ---------- rendering
    def clear_trees(self):
        for t in (self.tree_exact, self.tree_sim):
            t.delete(*t.get_children())
        self.iidmap.clear()

    def refresh(self):
        self.clear_trees()
        q = self.filter.get().strip().lower()
        limit = 3000
        for tree, groups, sim in ((self.tree_exact, self.exact, False), (self.tree_sim, self.similar, True)):
            gs = [g for g in groups if not q or any(q in f["path"].lower() for f in g)]
            if sim:
                gs.sort(key=lambda g: -len(g))
            else:
                gs.sort(key=lambda g: -g[0]["size"] * (len(g) - 1))
            for gi, g in enumerate(gs[:limit]):
                name = os.path.basename(g[0]["path"])
                if sim:
                    info = f"{name}   •   {len(g)} file, nama mirip, isi berbeda"
                else:
                    info = f"{name}   •   {len(g)} file × {fmt(g[0]['size'])}   •   boros {fmt(g[0]['size'] * (len(g) - 1))}"
                gid = tree.insert("", "end", text=info, open=True, tags=("grp",))
                for f in g:
                    iid = tree.insert(gid, "end", text="   " + os.path.basename(f["path"]))
                    self.iidmap[iid] = (g, f)
                    self.update_row(iid, tree, sim)
            if len(gs) > limit:
                tree.insert("", "end", text=f"… {len(gs) - limit} grup lain disembunyikan. Pakai kolom Cari untuk menyaring.")
        nd = sum(len(g) - 1 for g in self.exact)
        waste = sum(g[0]["size"] * (len(g) - 1) for g in self.exact)
        self.summary.set(f"📊  {getattr(self, 'total', 0):,} file dipindai   •   {len(self.exact):,} grup dobel   •   "
                         f"{nd:,} salinan   •   bisa hemat {fmt(waste)}   •   {len(self.similar):,} grup nama mirip")
        self.nb.tab(0, text=f"  Isi sama persis ({len(self.exact)})  ")
        self.nb.tab(1, text=f"  Nama mirip, cek manual ({len(self.similar)})  ")
        self.update_selinfo()

    def update_row(self, iid, tree=None, sim=None):
        g, f = self.iidmap[iid]
        if tree is None:
            tree = self.tree_exact if self.tree_exact.exists(iid) else self.tree_sim
        if sim is None:
            sim = tree is self.tree_sim
        if f["del"]:
            st, tag = "✗ HAPUS", "del"
        else:
            st, tag = ("✓ SIMPAN", "keep") if not sim else ("? cek", "chk")
        tree.item(iid, values=(st, fmt(f["size"]), fdate(f["mtime"]), os.path.dirname(f["path"])), tags=(tag,))

    def marked(self):
        seen, out = set(), []
        for g in self.exact + self.similar:
            for f in g:
                if f["del"] and f["path"] not in seen:
                    seen.add(f["path"])
                    out.append(f)
        return out

    def update_selinfo(self):
        m = self.marked()
        self.selinfo.set(f"{len(m):,} file ditandai hapus  •  {fmt(sum(f['size'] for f in m))}")
        self.btn_del["state"] = "normal" if m else "disabled"

    # ---------- events
    def on_click(self, ev):
        t = ev.widget
        if t.identify_region(ev.x, ev.y) == "cell" and t.identify_column(ev.x) == "#1":
            iid = t.identify_row(ev.y)
            if iid:
                t.selection_set(iid)
                self.toggle(iid)
                return "break"

    def on_double(self, ev):
        iid = ev.widget.identify_row(ev.y)
        if iid in self.iidmap:
            self.open_path(self.iidmap[iid][1]["path"])
            return "break"

    def on_right(self, ev):
        iid = ev.widget.identify_row(ev.y)
        if iid in self.iidmap:
            ev.widget.selection_set(iid)
            self.menu.tk_popup(ev.x_root, ev.y_root)

    def open_path(self, p):
        try:
            if IS_WIN:
                os.startfile(p)
            else:
                subprocess.Popen(["xdg-open", p])
        except Exception as ex:
            messagebox.showerror(APP, f"Tidak bisa membuka file:\n{ex}")

    def open_file(self):
        t, iid = self.current()
        if iid in self.iidmap:
            self.open_path(self.iidmap[iid][1]["path"])

    def open_loc(self):
        t, iid = self.current()
        if iid in self.iidmap:
            p = self.iidmap[iid][1]["path"]
            if IS_WIN:
                subprocess.Popen(f'explorer /select,"{p}"')
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(p)])

    def show_preview(self):
        t, iid = self.current()
        self.pvinfo.delete("1.0", "end")
        if iid not in self.iidmap:
            self.pv.configure(image="", text="Pilih file untuk melihat")
            return
        g, f = self.iidmap[iid]
        p = f["path"]
        self.pvinfo.insert("end", f"{os.path.basename(p)}\n\nFolder:\n{os.path.dirname(p)}\n\n"
                                  f"Ukuran: {fmt(f['size'])}\nDiubah: {fdate(f['mtime'])}\n"
                                  f"Status: {'akan dipindah ke Recycle Bin' if f['del'] else 'disimpan'}\n"
                                  f"Grup ini: {len(g)} file")
        cat = EXT2CAT.get(ext_of(p), "Lainnya")
        if Image and cat == "Gambar" and ext_of(p) not in ("svg", "raw", "cr2", "nef", "arw", "dng", "heic", "heif", "psd"):
            try:
                im = Image.open(p)
                im.thumbnail((300, 240))
                self.preview_img = ImageTk.PhotoImage(im)
                self.pv.configure(image=self.preview_img, text="", width=300, height=240)
                return
            except Exception:
                pass
        icon = {"Gambar": "🖼", "Video": "🎬", "Audio": "🎵", "Dokumen": "📄", "Arsip/Installer": "📦"}.get(cat, "📎")
        self.preview_img = None
        self.pv.configure(image="", text=f"{icon}\n.{ext_of(p).upper()}\n\nKlik dua kali untuk membuka",
                          font=("Segoe UI", 14), width=40, height=14)

    # ---------- export / delete
    def export_csv(self):
        if not self.exact and not self.similar:
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="hasil-scan-file-dobel.csv",
                                         filetypes=[("CSV", "*.csv")])
        if not p:
            return
        with open(p, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(["grup", "jenis", "status", "nama", "folder", "ukuran_byte", "ukuran", "diubah"])
            for kind, gs in (("isi sama", self.exact), ("nama mirip", self.similar)):
                for i, g in enumerate(gs, 1):
                    for f in g:
                        w.writerow([i, kind, "hapus" if f["del"] else "simpan", os.path.basename(f["path"]),
                                    os.path.dirname(f["path"]), f["size"], fmt(f["size"]), fdate(f["mtime"])])
        self.status.set(f"CSV disimpan: {p}")

    def delete_selected(self):
        m = self.marked()
        if not m:
            return
        total = sum(f["size"] for f in m)
        if send2trash:
            where = "dipindahkan ke Recycle Bin (masih bisa dikembalikan)"
        else:
            where = "dipindahkan ke folder _Duplikat_SmartScan di drive masing-masing"
        if not messagebox.askyesno(APP, f"{len(m):,} file ({fmt(total)}) akan {where}.\n\n"
                                        f"Satu salinan di setiap grup tetap disimpan.\n\nLanjutkan?"):
            return
        self.btn_del["state"] = "disabled"
        self.btn_scan["state"] = "disabled"
        threading.Thread(target=self._do_delete, args=(m,), daemon=True).start()

    def _do_delete(self, files):
        ok, fail = [], []
        for i, f in enumerate(files):
            p = f["path"]
            try:
                if send2trash:
                    send2trash(p)
                else:
                    drive, rest = os.path.splitdrive(os.path.abspath(p))
                    dest = os.path.join(drive + os.sep, "_Duplikat_SmartScan", rest.lstrip("\\/"))
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    shutil.move(p, dest)
                ok.append(f)
            except Exception as ex:
                fail.append((p, str(ex)))
            if i % 5 == 0:
                self.q.put(("status", f"Memindahkan {i + 1:,}/{len(files):,}  |  {p}", (i + 1) / len(files)))
        self.q.put(("deldone", ok, fail))

    def after_delete(self, ok, fail):
        gone = {f["path"] for f in ok}
        prune = lambda gs: [g for g in ([f for f in g if f["path"] not in gone] for g in gs) if len(g) > 1]
        self.exact, self.similar = prune(self.exact), prune(self.similar)
        self.btn_scan["state"] = "normal"
        freed = sum(f["size"] for f in ok)
        self.refresh()
        msg = f"{len(ok):,} file dipindahkan, ruang {fmt(freed)} dibebaskan."
        if not send2trash:
            msg += "\nFile ada di folder _Duplikat_SmartScan. Hapus folder itu kalau sudah yakin."
        else:
            msg += "\nKosongkan Recycle Bin supaya ruangnya benar-benar lega."
        if fail:
            msg += f"\n\n{len(fail)} file gagal (mungkin sedang dipakai / tidak ada izin):\n" + \
                   "\n".join(p for p, _ in fail[:8])
        self.status.set(msg.split("\n")[0])
        messagebox.showinfo(APP, msg)


if __name__ == "__main__":
    if IS_WIN:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    App().mainloop()
