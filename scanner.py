import os
import zipfile
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import threading
import json
import hashlib
from datetime import datetime

try:
    from androguard.core.bytecodes.apk import APK
except ImportError:
    print("Please install androguard using: pip install androguard")
    exit(1)

class APKScanner:
    def __init__(self):
        self.root = tk.Tk()
        self.is_dark_mode = False
        self.light_colors = {
            'primary': '#ecf0f1',
            'secondary': '#3498db',
            'success': '#27ae60',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'light': '#ffffff',
            'dark': '#34495e',
            'accent': '#8e44ad',
            'text': '#222222'
        }
        self.dark_colors = {
            'primary': '#23272e',
            'secondary': '#2980b9',
            'success': '#27ae60',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'light': '#2c2f34',
            'dark': '#1a1c22',
            'accent': '#9b59b6',
            'text': '#f8f8f2'
        }
        self.colors = self.light_colors.copy()
        self.setup_ui()
        self.scan_results = {}
        self.current_apk_path = None
        self.scan_thread = None
        self.stop_scan_flag = False
                # Dark Mode Toggle Button (bottom-right corner)
        self.dark_mode_var = tk.BooleanVar(value=self.is_dark_mode)
        self.toggle_btn = tk.Checkbutton(self.root, text="Dark Mode", variable=self.dark_mode_var, command=self.toggle_dark_mode, bg=self.light_colors['primary'], fg=self.light_colors['text'], anchor='w')
        self.toggle_btn.place(relx=1.0, rely=1.0, x=-10, y=-1, anchor='se')


    def setup_ui(self):
        self.root.title("Android APK Security Analyzer v3.0")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        self.style = ttk.Style()
        self.apply_theme()
        self.setup_menu()
        self.setup_main_interface()
        self.setup_status_bar()

    def apply_theme(self):
        c = self.colors
        self.style.theme_use('clam')
        self.style.configure('TFrame', background=c['primary'])
        self.style.configure('TLabel', background=c['primary'], foreground=c['text'])
        self.style.configure('TButton', background=c['secondary'], foreground=c['text'], font=('Segoe UI', 10, 'bold'))
        self.style.configure('TNotebook', background=c['dark'])
        self.style.configure('TNotebook.Tab', background=c['secondary'], foreground=c['text'], font=('Segoe UI', 10, 'bold'))
        self.style.map('TNotebook.Tab', background=[('selected', c['accent'])])
        self.style.configure('Treeview', background=c['light'], fieldbackground=c['light'], foreground=c['text'])
        self.style.configure('TProgressbar', background=c['accent'])
        self.style.configure('TLabelframe', background=c['primary'], foreground=c['text'])
        self.style.configure('TLabelframe.Label', background=c['primary'], foreground=c['accent'])
        self.root.configure(bg=c['primary'])

        # Update colors for classic widgets if already created
        if hasattr(self, 'info_text'):
            self.info_text.configure(bg=c['light'], fg=c['text'])
        if hasattr(self, 'overview_text'):
            self.overview_text.configure(bg=c['light'], fg=c['text'])
        if hasattr(self, 'security_text'):
            self.security_text.configure(bg=c['light'], fg=c['text'])
        if hasattr(self, 'cert_text'):
            self.cert_text.configure(bg=c['light'], fg=c['text'])
        if hasattr(self, 'raw_text'):
            self.raw_text.configure(bg=c['light'], fg=c['text'])

    def toggle_dark_mode(self):
        self.is_dark_mode = not self.is_dark_mode
        self.colors = self.dark_colors.copy() if self.is_dark_mode else self.light_colors.copy()
        self.apply_theme()

    def setup_menu(self):
        menubar = tk.Menu(self.root, bg=self.colors['primary'], fg=self.colors['text'])
        self.root.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['primary'], fg=self.colors['text'])
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open APK", command=self.browse_file, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Export Results (JSON)", command=lambda: self.export_results('json'))
        file_menu.add_command(label="Export Results (HTML)", command=lambda: self.export_results('html'))
        file_menu.add_command(label="Export Results (TXT)", command=lambda: self.export_results('txt'))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['primary'], fg=self.colors['text'])
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Batch Scan", command=self.batch_scan)
        tools_menu.add_command(label="Compare APKs", command=self.compare_apks)
        tools_menu.add_command(label="Hash Calculator", command=self.show_hash_calculator)
        tools_menu.add_separator()
        tools_menu.add_command(label="Toggle Dark Mode", command=self.toggle_dark_mode)
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['primary'], fg=self.colors['text'])
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Clear Results", command=self.clear_results)
        view_menu.add_command(label="Refresh", command=self.refresh_analysis)
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['primary'], fg=self.colors['text'])
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="Security Best Practices", command=self.show_security_guide)
        help_menu.add_command(label="About", command=self.show_about)
        self.root.bind('<Control-o>', lambda e: self.browse_file())
        self.root.bind('<F5>', lambda e: self.refresh_analysis())

    def setup_main_interface(self):
        main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        left_panel = ttk.Frame(main_container, style='TFrame')
        main_container.add(left_panel, weight=1)
        right_panel = ttk.Frame(main_container, style='TFrame')
        main_container.add(right_panel, weight=3)
        self.setup_left_panel(left_panel)
        self.setup_right_panel(right_panel)

    def setup_left_panel(self, parent):
        file_frame = ttk.LabelFrame(parent, text="APK File Selection", padding=10, style='TLabelframe')
        file_frame.pack(fill=tk.X, pady=(0, 10))
        self.file_path_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, state="readonly", font=('Consolas', 10))
        file_entry.pack(fill=tk.X, pady=(0, 5))
        browse_btn = ttk.Button(file_frame, text="Browse APK File", command=self.browse_file)
        browse_btn.pack(fill=tk.X)
        self.info_frame = ttk.LabelFrame(parent, text="Quick Info", padding=10, style='TLabelframe')
        self.info_frame.pack(fill=tk.X, pady=(0, 10))
        self.info_text = tk.Text(self.info_frame, height=8, wrap=tk.WORD, state="disabled",
                                 bg=self.colors['light'], fg=self.colors['text'], font=("Consolas", 9))
        self.info_text.pack(fill=tk.BOTH, expand=True)
        options_frame = ttk.LabelFrame(parent, text="Scan Options", padding=10, style='TLabelframe')
        options_frame.pack(fill=tk.X, pady=(0, 10))
        self.deep_scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Deep Analysis", variable=self.deep_scan_var).pack(anchor=tk.W)
        self.check_certificates_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Certificate Analysis", variable=self.check_certificates_var).pack(anchor=tk.W)
        self.api_analysis_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="API Usage Analysis", variable=self.api_analysis_var).pack(anchor=tk.W)
        progress_frame = ttk.LabelFrame(parent, text="Scan Progress", padding=10, style='TLabelframe')
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        self.progress_var = tk.StringVar(value="Ready")
        self.progress_label = ttk.Label(progress_frame, textvariable=self.progress_var, style='TLabel')
        self.progress_label.pack(fill=tk.X)
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate', style='TProgressbar')
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        action_frame = ttk.Frame(parent, style='TFrame')
        action_frame.pack(fill=tk.X, pady=(0, 10))
        self.scan_btn = ttk.Button(action_frame, text="Start Scan", command=self.start_scan, state="disabled")
        self.scan_btn.pack(fill=tk.X, pady=(0, 5))
        self.stop_btn = ttk.Button(action_frame, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(fill=tk.X)

    def setup_right_panel(self, parent):
        self.notebook = ttk.Notebook(parent, style='TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.overview_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.overview_frame, text="Overview")
        self.overview_text = scrolledtext.ScrolledText(
            self.overview_frame, wrap=tk.WORD, font=("Consolas", 10),
            bg=self.colors['light'], fg=self.colors['text']
        )
        self.overview_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.permissions_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.permissions_frame, text="Permissions")
        perm_container = ttk.Frame(self.permissions_frame, style='TFrame')
        perm_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.permissions_tree = ttk.Treeview(perm_container, columns=("Status", "Risk", "Usage"), show="tree headings")
        self.permissions_tree.heading("#0", text="Permission")
        self.permissions_tree.heading("Status", text="Status")
        self.permissions_tree.heading("Risk", text="Risk Level")
        self.permissions_tree.heading("Usage", text="API Usage")
        perm_scrollbar = ttk.Scrollbar(perm_container, orient=tk.VERTICAL, command=self.permissions_tree.yview)
        self.permissions_tree.configure(yscrollcommand=perm_scrollbar.set)
        self.permissions_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        perm_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.security_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.security_frame, text="Security Analysis")
        self.security_text = scrolledtext.ScrolledText(
            self.security_frame, wrap=tk.WORD, font=("Consolas", 10),
            bg=self.colors['light'], fg=self.colors['text']
        )
        self.security_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.cert_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.cert_frame, text="Certificates")
        self.cert_text = scrolledtext.ScrolledText(
            self.cert_frame, wrap=tk.WORD, font=("Consolas", 10),
            bg=self.colors['light'], fg=self.colors['text']
        )
        self.cert_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.raw_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.raw_frame, text="Raw Results")
        self.raw_text = scrolledtext.ScrolledText(
            self.raw_frame, wrap=tk.WORD, font=("Consolas", 9),
            bg=self.colors['light'], fg=self.colors['text']
        )
        self.raw_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_status_bar(self):
        self.status_frame = ttk.Frame(self.root, style='TFrame')
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_var = tk.StringVar(value="Ready - Select an APK file to begin analysis")
        self.status_label = ttk.Label(self.status_frame, textvariable=self.status_var, style='TLabel')
        self.status_label.pack(side=tk.LEFT, padx=5, pady=2)
        self.file_info_var = tk.StringVar()
        self.file_info_label = ttk.Label(self.status_frame, textvariable=self.file_info_var, style='TLabel')
        self.file_info_label.pack(side=tk.RIGHT, padx=5, pady=2)

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select APK File",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")]
        )
        if file_path:
            self.current_apk_path = file_path
            self.file_path_var.set(file_path)
            file_size = os.path.getsize(file_path) / (1024*1024)
            self.file_info_var.set(f"Size: {file_size:.1f} MB")
            self.status_var.set("APK file loaded - Click 'Start Scan' to analyze")
            self.scan_btn.config(state="normal")
            self.show_quick_info(file_path)

    def show_quick_info(self, file_path):
        self.info_text.config(state="normal")
        self.info_text.delete(1.0, tk.END)
        try:
            info = f"📦 File: {os.path.basename(file_path)}\n"
            info += f"📁 Size: {os.path.getsize(file_path) / (1024*1024):.1f} MB\n"
            info += f"📅 Modified: {datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M')}\n"
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            info += f"🔐 MD5: {file_hash[:16]}...\n"
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_file:
                    files = zip_file.namelist()
                    info += f"🗂️ Files: {len(files)}\n"
                    key_files = ['AndroidManifest.xml', 'classes.dex', 'resources.arsc']
                    for kf in key_files:
                        status = "✅" if kf in files else "❌"
                        info += f"  {status} {kf}\n"
            except:
                info += "❌ Invalid ZIP/APK structure\n"
            self.info_text.insert(tk.END, info)
        except Exception as e:
            self.info_text.insert(tk.END, f"❌ Error reading file: {str(e)}")
        self.info_text.config(state="disabled")

    def start_scan(self):
        if not self.current_apk_path:
            messagebox.showwarning("No File", "Please select an APK file first.")
            return
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress_bar.start()
        self.progress_var.set("Initializing scan...")
        self.stop_scan_flag = False
        self.clear_results()
        self.scan_thread = threading.Thread(target=self.perform_scan, daemon=True)
        self.scan_thread.start()

    def perform_scan(self):
        try:
            apk_path = self.current_apk_path
            self.root.after(0, lambda: self.progress_var.set("Loading APK..."))
            if self.stop_scan_flag:
                return
            try:
                apk = APK(apk_path)
            except Exception:
                with open(apk_path, 'rb') as f:
                    apk_data = f.read()
                apk = APK(apk_data, raw=True)
            self.root.after(0, lambda: self.progress_var.set("Extracting basic information..."))
            if self.stop_scan_flag:
                return
            results = {
                'file_info': {
                    'path': apk_path,
                    'size': os.path.getsize(apk_path),
                    'name': os.path.basename(apk_path),
                    'hash': {
                        'md5': self.calculate_hash(apk_path, 'md5'),
                        'sha1': self.calculate_hash(apk_path, 'sha1'),
                        'sha256': self.calculate_hash(apk_path, 'sha256')
                    }
                },
                'app_info': {
                    'name': apk.get_app_name() or "Unknown",
                    'package': apk.get_package() or "Unknown",
                    'version_name': apk.get_androidversion_name() or "Unknown",
                    'version_code': apk.get_androidversion_code() or "Unknown",
                    'main_activity': apk.get_main_activity() or "Unknown",
                    'min_sdk': apk.get_min_sdk_version() or "Unknown",
                    'target_sdk': apk.get_target_sdk_version() or "Unknown"
                },
                'permissions': apk.get_permissions(),
                'activities': apk.get_activities(),
                'services': apk.get_services(),
                'receivers': apk.get_receivers(),
                'providers': apk.get_providers()
            }
            if self.api_analysis_var.get() and not self.stop_scan_flag:
                self.root.after(0, lambda: self.progress_var.set("Analyzing permissions..."))
                results['permission_analysis'] = self.analyze_permissions(apk, results['permissions'])
            if self.check_certificates_var.get() and not self.stop_scan_flag:
                self.root.after(0, lambda: self.progress_var.set("Analyzing certificates..."))
                results['certificates'] = self.analyze_certificates(apk)
            if not self.stop_scan_flag:
                self.root.after(0, lambda: self.progress_var.set("Performing security analysis..."))
                results['security_analysis'] = self.perform_security_analysis(results)
            self.scan_results = results
            if not self.stop_scan_flag:
                self.root.after(0, lambda: self.display_results())
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            self.root.after(0, lambda: self.show_error(error_msg))
        finally:
            self.root.after(0, self.scan_complete)

    def calculate_hash(self, file_path, algorithm):
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def analyze_permissions(self, apk, permissions):
        analysis = {
            'total': len(permissions),
            'suspicious': [],
            'high_risk': [],
            'medium_risk': [],
            'low_risk': [],
            'unknown': []
        }
        high_risk_perms = [
            "android.permission.SEND_SMS",
            "android.permission.CALL_PHONE",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG"
        ]
        medium_risk_perms = [
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.INTERNET",
            "android.permission.WAKE_LOCK",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.RECEIVE_BOOT_COMPLETED"
        ]
        for perm in permissions:
            if perm in high_risk_perms:
                analysis['high_risk'].append(perm)
            elif perm in medium_risk_perms:
                analysis['medium_risk'].append(perm)
            else:
                analysis['low_risk'].append(perm)
        return analysis

    def analyze_certificates(self, apk):
        try:
            certificates = apk.get_certificates()
            cert_analysis = []
            for cert in certificates:
                cert_info = {
                    'subject': str(cert.subject),
                    'issuer': str(cert.issuer),
                    'serial_number': str(cert.serial_number),
                    'not_valid_before': str(cert.not_valid_before),
                    'not_valid_after': str(cert.not_valid_after),
                    'is_self_signed': cert.subject == cert.issuer,
                    'signature_algorithm': str(cert.signature_algorithm_oid._name)
                }
                cert_analysis.append(cert_info)
            return cert_analysis
        except Exception as e:
            return [{'error': f"Certificate analysis failed: {str(e)}"}]

    def perform_security_analysis(self, results):
        analysis = {
            'risk_score': 0,
            'issues': [],
            'recommendations': [],
            'flags': []
        }
        permissions = results.get('permissions', [])
        dangerous_combos = [
            (['android.permission.SEND_SMS', 'android.permission.RECEIVE_SMS'], 'SMS manipulation capability'),
            (['android.permission.RECORD_AUDIO', 'android.permission.INTERNET'], 'Audio recording with network access'),
            (['android.permission.CAMERA', 'android.permission.INTERNET'], 'Camera access with network capability'),
            (['android.permission.ACCESS_FINE_LOCATION', 'android.permission.INTERNET'], 'Location tracking with network access')
        ]
        for combo, description in dangerous_combos:
            if all(perm in permissions for perm in combo):
                analysis['issues'].append(f"Dangerous combination: {description}")
                analysis['risk_score'] += 20
        if len(permissions) > 20:
            analysis['flags'].append(f"High permission count: {len(permissions)} permissions requested")
            analysis['risk_score'] += 10
        admin_perms = [p for p in permissions if 'ADMIN' in p or 'DEVICE_ADMIN' in p]
        if admin_perms:
            analysis['flags'].append("Requests device admin privileges")
            analysis['risk_score'] += 30
        if analysis['risk_score'] > 50:
            analysis['recommendations'].append("High risk score - review permissions carefully")
        if analysis['risk_score'] > 30:
            analysis['recommendations'].append("Medium risk - verify app legitimacy")
        if not analysis['issues']:
            analysis['recommendations'].append("No major security issues detected")
        return analysis

    def display_results(self):
        if not self.scan_results:
            return
        self.display_overview()
        self.display_permissions()
        self.display_security_analysis()
        self.display_certificates()
        self.display_raw_results()
        self.status_var.set("Scan completed successfully")

    def display_overview(self):
        self.overview_text.delete(1.0, tk.END)
        results = self.scan_results
        overview = f"""
📦 APK ANALYSIS OVERVIEW
{'='*50}

📋 File Information:
  • Name: {results['file_info']['name']}
  • Size: {results['file_info']['size'] / (1024*1024):.1f} MB
  • MD5: {results['file_info']['hash']['md5']}
  • SHA256: {results['file_info']['hash']['sha256'][:32]}...

📱 Application Information:
  • App Name: {results['app_info']['name']}
  • Package: {results['app_info']['package']}
  • Version: {results['app_info']['version_name']} ({results['app_info']['version_code']})
  • Main Activity: {results['app_info']['main_activity']}
  • Min SDK: {results['app_info']['min_sdk']}
  • Target SDK: {results['app_info']['target_sdk']}

📊 Component Summary:
  • Permissions: {len(results['permissions'])}
  • Activities: {len(results['activities'])}
  • Services: {len(results['services'])}
  • Receivers: {len(results['receivers'])}
  • Providers: {len(results['providers'])}

🔒 Security Score: {results.get('security_analysis', {}).get('risk_score', 0)}/100
"""
        self.overview_text.insert(tk.END, overview)

    def display_permissions(self):
        for item in self.permissions_tree.get_children():
            self.permissions_tree.delete(item)
        if 'permission_analysis' not in self.scan_results:
            return
        perm_analysis = self.scan_results['permission_analysis']
        categories = [
            ("High Risk", perm_analysis['high_risk'], "🔴"),
            ("Medium Risk", perm_analysis['medium_risk'], "🟡"),
            ("Low Risk", perm_analysis['low_risk'], "🟢")
        ]
        for category, perms, icon in categories:
            if perms:
                category_item = self.permissions_tree.insert("", tk.END, text=f"{icon} {category} ({len(perms)})",
                                                           values=("", "", ""))
                for perm in perms:
                    self.permissions_tree.insert(category_item, tk.END, text=perm,
                                               values=("Declared", category.split()[0], "Unknown"))

    def display_security_analysis(self):
        self.security_text.delete(1.0, tk.END)
        if 'security_analysis' not in self.scan_results:
            return
        security = self.scan_results['security_analysis']
        analysis = f"""
🔒 SECURITY ANALYSIS
{'='*50}

Risk Score: {security['risk_score']}/100

🚨 Security Issues:
"""
        if security['issues']:
            for issue in security['issues']:
                analysis += f"  • {issue}\n"
        else:
            analysis += "  ✅ No major security issues detected\n"
        analysis += f"""
🚩 Security Flags:
"""
        if security['flags']:
            for flag in security['flags']:
                analysis += f"  • {flag}\n"
        else:
            analysis += "  ✅ No security flags raised\n"
        analysis += f"""
💡 Recommendations:
"""
        for rec in security['recommendations']:
            analysis += f"  • {rec}\n"
        self.security_text.insert(tk.END, analysis)

    def display_certificates(self):
        self.cert_text.delete(1.0, tk.END)
        if 'certificates' not in self.scan_results:
            return
        certificates = self.scan_results['certificates']
        cert_info = f"""
🔐 CERTIFICATE ANALYSIS
{'='*50}

Total Certificates: {len(certificates)}

"""
        for i, cert in enumerate(certificates, 1):
            if 'error' in cert:
                cert_info += f"Certificate {i}: {cert['error']}\n"
                continue
            cert_info += f"""
Certificate {i}:
  • Subject: {cert['subject']}
  • Issuer: {cert['issuer']}
  • Valid From: {cert['not_valid_before']}
  • Valid Until: {cert['not_valid_after']}
  • Self-Signed: {cert['is_self_signed']}
  • Algorithm: {cert['signature_algorithm']}

"""
        self.cert_text.insert(tk.END, cert_info)

    def display_raw_results(self):
        self.raw_text.delete(1.0, tk.END)
        try:
            raw_json = json.dumps(self.scan_results, indent=2, default=str)
            self.raw_text.insert(tk.END, raw_json)
        except Exception as e:
            self.raw_text.insert(tk.END, f"Error displaying raw results: {str(e)}")

    def show_error(self, message):
        messagebox.showerror("Scan Error", message)
        self.status_var.set(f"Error: {message}")
        self.progress_var.set("")

    def scan_complete(self):
        self.progress_bar.stop()
        self.progress_var.set("Scan complete.")
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set("Scan complete. Ready for next operation.")

    def stop_scan(self):
        self.stop_scan_flag = True
        self.progress_var.set("Stopping scan...")
        self.status_var.set("Scan stopped by user.")
        self.progress_bar.stop()
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def clear_results(self):
        self.scan_results = {}
        self.overview_text.delete(1.0, tk.END)
        self.security_text.delete(1.0, tk.END)
        self.cert_text.delete(1.0, tk.END)
        self.raw_text.delete(1.0, tk.END)
        for item in self.permissions_tree.get_children():
            self.permissions_tree.delete(item)
        self.status_var.set("Results cleared.")

    def refresh_analysis(self):
        if self.current_apk_path:
            self.start_scan()
        else:
            messagebox.showinfo("No APK", "Please select an APK file first.")

    def export_results(self, fmt):
        if not self.scan_results:
            messagebox.showinfo("No Results", "No scan results to export.")
            return
        filetypes = {
            'json': ("JSON files", "*.json"),
            'html': ("HTML files", "*.html"),
            'txt': ("Text files", "*.txt")
        }
        ext = fmt
        file_path = filedialog.asksaveasfilename(
            defaultextension=f".{ext}",
            filetypes=[filetypes[fmt], ("All files", "*.*")]
        )
        if not file_path:
            return
        try:
            if fmt == 'json':
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.scan_results, f, indent=2, default=str)
            elif fmt == 'txt':
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.overview_text.get(1.0, tk.END))
                    f.write("\n\n")
                    f.write(self.security_text.get(1.0, tk.END))
            elif fmt == 'html':
                html = "<html><body>"
                html += "<h2>APK Analysis Overview</h2><pre>{}</pre>".format(self.overview_text.get(1.0, tk.END))
                html += "<h2>Security Analysis</h2><pre>{}</pre>".format(self.security_text.get(1.0, tk.END))
                html += "</body></html>"
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html)
            messagebox.showinfo("Export Successful", f"Results exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results: {e}")

    def batch_scan(self):
        messagebox.showinfo("Batch Scan", "Batch scan feature is not implemented yet.")

    def compare_apks(self):
        messagebox.showinfo("Compare APKs", "APK comparison feature is not implemented yet.")

    def show_hash_calculator(self):
        messagebox.showinfo("Hash Calculator", "Hash calculator feature is not implemented yet.")

    def show_user_guide(self):
        guide = (
            "1. Click 'Open APK' to select an APK file.\n"
            "2. Review quick info, then click 'Start Scan' to analyze.\n"
            "3. Browse results in the tabs.\n"
            "4. Export results using the File menu.\n"
            "5. Use the Tools menu for extra features."
        )
        messagebox.showinfo("User Guide", guide)

    def show_security_guide(self):
        guide = (
            "Security Best Practices:\n"
            "- Only install APKs from trusted sources.\n"
            "- Review app permissions carefully.\n"
            "- Avoid apps requesting excessive or dangerous permissions.\n"
            "- Keep your device and apps updated.\n"
            "- Use security software where appropriate."
        )
        messagebox.showinfo("Security Best Practices", guide)

    def show_about(self):
        about = (
            "Android APK Security Analyzer v3.0\n"
            "Developed with Androguard and Tkinter.\n"
            "For educational and research purposes."
        )
        messagebox.showinfo("About", about)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = APKScanner()
    app.run()