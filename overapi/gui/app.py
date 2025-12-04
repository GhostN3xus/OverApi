"""
OverApi GUI Application - Professional Tkinter Interface
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List
import webbrowser

from overapi.core.config import Config, ScanMode, ProxyConfig
from overapi.core.logger import Logger
from overapi.scanners.orchestrator import Orchestrator
from overapi.reports.report_generator import ReportGenerator


class OverApiApp:
    """Main GUI Application for OverApi Scanner."""

    def __init__(self, root: tk.Tk):
        """Initialize the application."""
        self.root = root
        self.root.title("OverApi - API Security Scanner v2.0.0")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)

        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self._configure_styles()

        # Application state
        self.scan_running = False
        self.scan_results = None
        self.logger = None

        # Create UI
        self._create_menu()
        self._create_main_layout()

        # Center window
        self._center_window()

    def _configure_styles(self):
        """Configure custom styles."""
        # Colors
        bg_dark = '#2b2b2b'
        bg_light = '#3c3c3c'
        fg_color = '#ffffff'
        accent = '#4a9eff'
        success = '#28a745'
        danger = '#dc3545'
        warning = '#ffc107'

        # Configure styles
        self.style.configure('Title.TLabel',
                           font=('Helvetica', 16, 'bold'),
                           foreground=accent)

        self.style.configure('Header.TLabel',
                           font=('Helvetica', 12, 'bold'),
                           foreground=fg_color,
                           background=bg_light,
                           padding=10)

        self.style.configure('Success.TLabel',
                           foreground=success,
                           font=('Helvetica', 10, 'bold'))

        self.style.configure('Danger.TLabel',
                           foreground=danger,
                           font=('Helvetica', 10, 'bold'))

        self.style.configure('Warning.TLabel',
                           foreground=warning,
                           font=('Helvetica', 10, 'bold'))

        self.style.configure('Accent.TButton',
                           font=('Helvetica', 10, 'bold'),
                           padding=10)

    def _create_menu(self):
        """Create menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Scan", command=self._clear_form)
        file_menu.add_command(label="Load Config", command=self._load_config)
        file_menu.add_command(label="Save Config", command=self._save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Wordlist Manager", command=self._open_wordlist_manager)
        tools_menu.add_command(label="Vulnerability Database", command=self._open_vuln_db)
        tools_menu.add_command(label="Plugin Manager", command=self._open_plugin_manager)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self._open_docs)
        help_menu.add_command(label="About", command=self._show_about)

    def _create_main_layout(self):
        """Create main application layout."""
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create tabs
        self.scan_tab = ttk.Frame(self.notebook)
        self.results_tab = ttk.Frame(self.notebook)
        self.logs_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.scan_tab, text="🔍 Scan Configuration")
        self.notebook.add(self.results_tab, text="📊 Results")
        self.notebook.add(self.logs_tab, text="📝 Logs")

        # Build each tab
        self._build_scan_tab()
        self._build_results_tab()
        self._build_logs_tab()

    def _build_scan_tab(self):
        """Build scan configuration tab."""
        # Create scrollable frame
        canvas = tk.Canvas(self.scan_tab)
        scrollbar = ttk.Scrollbar(self.scan_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Target Configuration
        target_frame = ttk.LabelFrame(scrollable_frame, text="🎯 Target Configuration", padding=15)
        target_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=10, pady=5)

        ttk.Label(target_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(target_frame, width=50)
        self.url_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        self.url_entry.insert(0, "https://api.example.com")

        ttk.Label(target_frame, text="API Type:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.api_type_var = tk.StringVar(value="auto")
        api_type_combo = ttk.Combobox(target_frame, textvariable=self.api_type_var,
                                      values=["auto", "rest", "graphql", "soap", "grpc", "websocket"],
                                      state="readonly", width=15)
        api_type_combo.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)

        # Scan Options
        scan_frame = ttk.LabelFrame(scrollable_frame, text="⚙️ Scan Options", padding=15)
        scan_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=10, pady=5)

        ttk.Label(scan_frame, text="Scan Mode:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.mode_var = tk.StringVar(value="normal")
        for i, mode in enumerate(["safe", "normal", "aggressive"]):
            ttk.Radiobutton(scan_frame, text=mode.capitalize(),
                          variable=self.mode_var, value=mode).grid(row=0, column=i+1, sticky=tk.W, padx=5)

        ttk.Label(scan_frame, text="Threads:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.threads_var = tk.IntVar(value=10)
        threads_spin = ttk.Spinbox(scan_frame, from_=1, to=100, textvariable=self.threads_var, width=10)
        threads_spin.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)

        ttk.Label(scan_frame, text="Timeout (s):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.timeout_var = tk.IntVar(value=30)
        timeout_spin = ttk.Spinbox(scan_frame, from_=5, to=300, textvariable=self.timeout_var, width=10)
        timeout_spin.grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)

        # Security Options
        security_frame = ttk.LabelFrame(scrollable_frame, text="🔒 Security Options", padding=15)
        security_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=10, pady=5)

        self.verify_ssl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(security_frame, text="Verify SSL Certificates",
                       variable=self.verify_ssl_var).grid(row=0, column=0, sticky=tk.W, pady=2)

        ttk.Label(security_frame, text="Proxy:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.proxy_entry = ttk.Entry(security_frame, width=40)
        self.proxy_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        self.proxy_entry.insert(0, "")

        ttk.Label(security_frame, text="Custom Headers:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.headers_text = tk.Text(security_frame, height=3, width=40)
        self.headers_text.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        # Feature Options
        features_frame = ttk.LabelFrame(scrollable_frame, text="🎯 Feature Options", padding=15)
        features_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=10, pady=5)

        self.enable_fuzzing_var = tk.BooleanVar(value=True)
        self.enable_injection_var = tk.BooleanVar(value=True)
        self.enable_ratelimit_var = tk.BooleanVar(value=True)
        self.enable_bola_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(features_frame, text="Enable Fuzzing",
                       variable=self.enable_fuzzing_var).grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(features_frame, text="Enable Injection Tests",
                       variable=self.enable_injection_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Checkbutton(features_frame, text="Enable Rate Limit Tests",
                       variable=self.enable_ratelimit_var).grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(features_frame, text="Enable BOLA Tests",
                       variable=self.enable_bola_var).grid(row=1, column=1, sticky=tk.W, pady=2)

        # Output Options
        output_frame = ttk.LabelFrame(scrollable_frame, text="📁 Output Options", padding=15)
        output_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=10, pady=5)

        ttk.Label(output_frame, text="Output Directory:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.output_dir_var = tk.StringVar(value="./reports")
        ttk.Entry(output_frame, textvariable=self.output_dir_var, width=35).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        ttk.Button(output_frame, text="Browse", command=self._browse_output_dir).grid(row=0, column=2, pady=5, padx=5)

        self.generate_html_var = tk.BooleanVar(value=True)
        self.generate_json_var = tk.BooleanVar(value=True)
        self.generate_pdf_var = tk.BooleanVar(value=False)
        self.generate_csv_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(output_frame, text="HTML Report",
                       variable=self.generate_html_var).grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(output_frame, text="JSON Report",
                       variable=self.generate_json_var).grid(row=1, column=1, sticky=tk.W, pady=2)
        ttk.Checkbutton(output_frame, text="PDF Report",
                       variable=self.generate_pdf_var).grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(output_frame, text="CSV Report",
                       variable=self.generate_csv_var).grid(row=2, column=1, sticky=tk.W, pady=2)

        # Control Buttons
        control_frame = ttk.Frame(scrollable_frame)
        control_frame.grid(row=5, column=0, columnspan=2, pady=20)

        self.start_button = ttk.Button(control_frame, text="🚀 Start Scan",
                                       command=self._start_scan,
                                       style='Accent.TButton')
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="⏹️ Stop Scan",
                                      command=self._stop_scan,
                                      state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        ttk.Button(control_frame, text="🗑️ Clear",
                  command=self._clear_form).pack(side=tk.LEFT, padx=5)

        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(scrollable_frame, mode='indeterminate',
                                           variable=self.progress_var)
        self.progress_bar.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=10, pady=10)

        # Status Label
        self.status_label = ttk.Label(scrollable_frame, text="Ready to scan",
                                     style='Success.TLabel')
        self.status_label.grid(row=7, column=0, columnspan=2, pady=5)

        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _build_results_tab(self):
        """Build results tab."""
        # Results tree
        tree_frame = ttk.Frame(self.results_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create treeview
        columns = ('Type', 'Severity', 'Endpoint', 'Description')
        self.results_tree = ttk.Treeview(tree_frame, columns=columns, show='tree headings')

        # Configure columns
        self.results_tree.heading('#0', text='#')
        self.results_tree.heading('Type', text='Vulnerability Type')
        self.results_tree.heading('Severity', text='Severity')
        self.results_tree.heading('Endpoint', text='Endpoint')
        self.results_tree.heading('Description', text='Description')

        self.results_tree.column('#0', width=50)
        self.results_tree.column('Type', width=200)
        self.results_tree.column('Severity', width=100)
        self.results_tree.column('Endpoint', width=250)
        self.results_tree.column('Description', width=400)

        # Add scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.results_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Pack treeview and scrollbars
        self.results_tree.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        vsb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        hsb.grid(row=1, column=0, sticky=(tk.E, tk.W))

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Summary frame
        summary_frame = ttk.LabelFrame(self.results_tab, text="📊 Summary", padding=10)
        summary_frame.pack(fill=tk.X, padx=10, pady=10)

        self.summary_label = ttk.Label(summary_frame, text="No scan results yet")
        self.summary_label.pack()

        # Buttons frame
        buttons_frame = ttk.Frame(self.results_tab)
        buttons_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(buttons_frame, text="📄 Open HTML Report",
                  command=self._open_html_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="📊 Export JSON",
                  command=self._export_json).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="📑 Export PDF",
                  command=self._export_pdf).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="📈 Export CSV",
                  command=self._export_csv).pack(side=tk.LEFT, padx=5)

    def _build_logs_tab(self):
        """Build logs tab."""
        # Logs text area
        self.logs_text = scrolledtext.ScrolledText(self.logs_tab, wrap=tk.WORD,
                                                   font=('Consolas', 9))
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Buttons
        buttons_frame = ttk.Frame(self.logs_tab)
        buttons_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(buttons_frame, text="🗑️ Clear Logs",
                  command=lambda: self.logs_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="💾 Save Logs",
                  command=self._save_logs).pack(side=tk.LEFT, padx=5)

    def _start_scan(self):
        """Start security scan."""
        # Validate inputs
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a target URL")
            return

        # Update UI
        self.scan_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_bar.start(10)
        self.status_label.config(text="Scan in progress...", style='Warning.TLabel')
        self.logs_text.delete(1.0, tk.END)

        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Run scan in thread
        thread = threading.Thread(target=self._run_scan, daemon=True)
        thread.start()

    def _run_scan(self):
        """Run the actual scan (in thread)."""
        try:
            # Parse headers
            headers_text = self.headers_text.get(1.0, tk.END).strip()
            custom_headers = {}
            if headers_text:
                for line in headers_text.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        custom_headers[key.strip()] = value.strip()

            # Parse proxy
            proxy = None
            proxy_url = self.proxy_entry.get().strip()
            if proxy_url:
                proxy = ProxyConfig(http=proxy_url, https=proxy_url)

            # Create config
            api_type = self.api_type_var.get()
            if api_type == "auto":
                api_type = None

            config = Config(
                url=self.url_entry.get().strip(),
                api_type=api_type,
                mode=ScanMode(self.mode_var.get()),
                threads=self.threads_var.get(),
                timeout=self.timeout_var.get(),
                verify_ssl=self.verify_ssl_var.get(),
                proxy=proxy,
                custom_headers=custom_headers,
                output_dir=self.output_dir_var.get(),
                enable_fuzzing=self.enable_fuzzing_var.get(),
                enable_injection_tests=self.enable_injection_var.get(),
                enable_ratelimit_tests=self.enable_ratelimit_var.get(),
                enable_bola_tests=self.enable_bola_var.get(),
                verbose=True
            )

            # Create logger that writes to GUI
            self.logger = Logger(level=20, verbose=True)
            self._log("Starting OverApi scan...")
            self._log(f"Target: {config.url}")
            self._log(f"Mode: {config.mode.value}")

            # Run scan
            orchestrator = Orchestrator(config, self.logger)
            results = orchestrator.scan()

            self.scan_results = results

            # Generate reports
            self._log("\nGenerating reports...")
            report_gen = ReportGenerator(self.logger)

            output_html = None
            output_json = None
            output_pdf = None
            output_csv = None

            if self.generate_html_var.get():
                output_html = Path(config.output_dir) / f"report_{datetime.now():%Y%m%d_%H%M%S}.html"
            if self.generate_json_var.get():
                output_json = Path(config.output_dir) / f"report_{datetime.now():%Y%m%d_%H%M%S}.json"
            if self.generate_pdf_var.get():
                output_pdf = Path(config.output_dir) / f"report_{datetime.now():%Y%m%d_%H%M%S}.pdf"
            if self.generate_csv_var.get():
                output_csv = Path(config.output_dir) / f"report_{datetime.now():%Y%m%d_%H%M%S}.csv"

            report_gen.generate(
                results,
                output_html=str(output_html) if output_html else None,
                output_json=str(output_json) if output_json else None,
                output_dir=config.output_dir
            )

            # Update UI with results
            self.root.after(0, self._update_results, results)

            self._log("\n✅ Scan completed successfully!")

        except Exception as e:
            self._log(f"\n❌ Error during scan: {str(e)}")
            self.root.after(0, messagebox.showerror, "Scan Error", str(e))

        finally:
            # Update UI
            self.root.after(0, self._scan_finished)

    def _scan_finished(self):
        """Update UI when scan finishes."""
        self.scan_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_bar.stop()
        self.status_label.config(text="Scan completed", style='Success.TLabel')

    def _stop_scan(self):
        """Stop running scan."""
        # TODO: Implement scan cancellation
        self.scan_running = False
        self._scan_finished()
        self.status_label.config(text="Scan stopped by user", style='Danger.TLabel')

    def _update_results(self, results):
        """Update results tree with scan results."""
        # Clear existing results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Count vulnerabilities
        vuln_count = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }

        # Add vulnerabilities to tree
        if hasattr(results, 'vulnerabilities'):
            for i, vuln in enumerate(results.vulnerabilities, 1):
                severity = vuln.get('severity', 'INFO').upper()
                vuln_count[severity] = vuln_count.get(severity, 0) + 1

                self.results_tree.insert('', tk.END, text=str(i), values=(
                    vuln.get('type', 'Unknown'),
                    severity,
                    vuln.get('endpoint', 'N/A'),
                    vuln.get('description', '')[:100] + '...'
                ))

        # Update summary
        total = sum(vuln_count.values())
        summary_text = f"Total Vulnerabilities: {total} | "
        summary_text += f"🔴 Critical: {vuln_count['CRITICAL']} | "
        summary_text += f"🟠 High: {vuln_count['HIGH']} | "
        summary_text += f"🟡 Medium: {vuln_count['MEDIUM']} | "
        summary_text += f"🟢 Low: {vuln_count['LOW']} | "
        summary_text += f"ℹ️ Info: {vuln_count['INFO']}"

        self.summary_label.config(text=summary_text)

        # Switch to results tab
        self.notebook.select(self.results_tab)

    def _log(self, message: str):
        """Add message to logs."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        self.root.after(0, self.logs_text.insert, tk.END, log_message)
        self.root.after(0, self.logs_text.see, tk.END)

    def _clear_form(self):
        """Clear form fields."""
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, "https://api.example.com")
        self.api_type_var.set("auto")
        self.mode_var.set("normal")
        self.threads_var.set(10)
        self.timeout_var.set(30)
        self.verify_ssl_var.set(True)
        self.proxy_entry.delete(0, tk.END)
        self.headers_text.delete(1.0, tk.END)
        self.enable_fuzzing_var.set(True)
        self.enable_injection_var.set(True)
        self.enable_ratelimit_var.set(True)
        self.enable_bola_var.set(True)

    def _browse_output_dir(self):
        """Browse for output directory."""
        directory = filedialog.askdirectory()
        if directory:
            self.output_dir_var.set(directory)

    def _load_config(self):
        """Load configuration from file."""
        filename = filedialog.askopenfilename(
            title="Load Configuration",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    config = json.load(f)
                # TODO: Populate form from config
                messagebox.showinfo("Success", "Configuration loaded")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load config: {e}")

    def _save_config(self):
        """Save configuration to file."""
        filename = filedialog.asksaveasfilename(
            title="Save Configuration",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                config = {
                    'url': self.url_entry.get(),
                    'api_type': self.api_type_var.get(),
                    'mode': self.mode_var.get(),
                    'threads': self.threads_var.get(),
                    'timeout': self.timeout_var.get(),
                    'verify_ssl': self.verify_ssl_var.get(),
                    'proxy': self.proxy_entry.get(),
                    'headers': self.headers_text.get(1.0, tk.END),
                    'output_dir': self.output_dir_var.get()
                }
                with open(filename, 'w') as f:
                    json.dump(config, f, indent=2)
                messagebox.showinfo("Success", "Configuration saved")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save config: {e}")

    def _open_wordlist_manager(self):
        """Open wordlist manager dialog."""
        messagebox.showinfo("Wordlist Manager", "Wordlist Manager - Coming soon!")

    def _open_vuln_db(self):
        """Open vulnerability database dialog."""
        messagebox.showinfo("Vulnerability Database", "Vulnerability Database - Coming soon!")

    def _open_plugin_manager(self):
        """Open plugin manager dialog."""
        messagebox.showinfo("Plugin Manager", "Plugin Manager - Coming soon!")

    def _open_html_report(self):
        """Open HTML report in browser."""
        if hasattr(self, 'last_html_report'):
            webbrowser.open(self.last_html_report)
        else:
            messagebox.showwarning("No Report", "No HTML report available")

    def _export_json(self):
        """Export results as JSON."""
        if not self.scan_results:
            messagebox.showwarning("No Results", "No scan results to export")
            return
        # TODO: Implement JSON export
        messagebox.showinfo("Export", "JSON export - Coming soon!")

    def _export_pdf(self):
        """Export results as PDF."""
        if not self.scan_results:
            messagebox.showwarning("No Results", "No scan results to export")
            return
        # TODO: Implement PDF export
        messagebox.showinfo("Export", "PDF export - Coming soon!")

    def _export_csv(self):
        """Export results as CSV."""
        if not self.scan_results:
            messagebox.showwarning("No Results", "No scan results to export")
            return
        # TODO: Implement CSV export
        messagebox.showinfo("Export", "CSV export - Coming soon!")

    def _save_logs(self):
        """Save logs to file."""
        filename = filedialog.asksaveasfilename(
            title="Save Logs",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.logs_text.get(1.0, tk.END))
                messagebox.showinfo("Success", "Logs saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {e}")

    def _open_docs(self):
        """Open documentation in browser."""
        webbrowser.open("https://github.com/GhostN3xus/OverApi")

    def _show_about(self):
        """Show about dialog."""
        about_text = """
OverApi - API Security Scanner v2.0.0

Professional API vulnerability scanner supporting:
• REST, GraphQL, SOAP, gRPC, WebSocket
• OWASP API Top 10 Testing
• JWT Analysis, SSRF Detection
• Business Logic Testing
• Fuzzing & Bypass Techniques

Developed for security professionals and penetration testers.

© 2024 GhostN3xus
        """
        messagebox.showinfo("About OverApi", about_text.strip())

    def _center_window(self):
        """Center window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')


def main():
    """Launch GUI application."""
    root = tk.Tk()
    app = OverApiApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
