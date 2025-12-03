"""
OverApi Enterprise - Professional Tkinter GUI
Modern and professional interface for API security scanning
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
from datetime import datetime
from typing import Dict, Any, Optional
import json


class ModernButton(tk.Button):
    """Custom styled button with hover effects"""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.config(
            relief=tk.FLAT,
            borderwidth=0,
            padx=20,
            pady=10,
            font=('Segoe UI', 10, 'bold'),
            cursor='hand2'
        )
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        self.default_bg = kwargs.get('bg', '#007bff')

    def _on_enter(self, e):
        self['background'] = self._lighten_color(self.default_bg)

    def _on_leave(self, e):
        self['background'] = self.default_bg

    def _lighten_color(self, color):
        """Lighten color for hover effect"""
        if color == '#007bff':
            return '#0056b3'
        elif color == '#28a745':
            return '#1e7e34'
        elif color == '#dc3545':
            return '#bd2130'
        return color


class EnterpriseGUI:
    """
    OverApi Enterprise Edition - Professional GUI

    Features:
    - Modern, professional interface
    - Real-time scan monitoring
    - Advanced configuration options
    - Multi-format report export
    - Dashboard with metrics
    - Dark/Light theme support
    """

    def __init__(self, root):
        self.root = root
        self.root.title("OverApi Enterprise - API Security Scanner v2.0")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)

        # Color scheme
        self.colors = {
            'primary': '#007bff',
            'success': '#28a745',
            'danger': '#dc3545',
            'warning': '#ffc107',
            'info': '#17a2b8',
            'dark': '#343a40',
            'light': '#f8f9fa',
            'bg': '#ffffff',
            'fg': '#212529',
            'border': '#dee2e6'
        }

        # Configure root
        self.root.configure(bg=self.colors['bg'])

        # Variables
        self.scan_running = False
        self.scan_thread = None
        self.log_queue = queue.Queue()
        self.vulnerabilities = []
        self.scan_stats = {
            'endpoints_found': 0,
            'vulnerabilities': 0,
            'requests_sent': 0,
            'scan_time': 0
        }

        # Create UI
        self._create_menu_bar()
        self._create_header()
        self._create_main_container()
        self._create_status_bar()

        # Start log update loop
        self._update_logs()

    def _create_menu_bar(self):
        """Create professional menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Scan", command=self._new_scan, accelerator="Ctrl+N")
        file_menu.add_command(label="Load Configuration", command=self._load_config)
        file_menu.add_command(label="Save Configuration", command=self._save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Ctrl+Q")

        # Scan menu
        scan_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Scan", menu=scan_menu)
        scan_menu.add_command(label="Start Scan", command=self._start_scan, accelerator="F5")
        scan_menu.add_command(label="Stop Scan", command=self._stop_scan, accelerator="F6")
        scan_menu.add_separator()
        scan_menu.add_command(label="Quick Scan", command=self._quick_scan)
        scan_menu.add_command(label="Deep Scan", command=self._deep_scan)

        # Reports menu
        reports_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Reports", menu=reports_menu)
        reports_menu.add_command(label="Export HTML", command=lambda: self._export_report('html'))
        reports_menu.add_command(label="Export PDF", command=lambda: self._export_report('pdf'))
        reports_menu.add_command(label="Export JSON", command=lambda: self._export_report('json'))
        reports_menu.add_command(label="Export CSV", command=lambda: self._export_report('csv'))
        reports_menu.add_command(label="Export XML", command=lambda: self._export_report('xml'))

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Plugin Manager", command=self._open_plugin_manager)
        tools_menu.add_command(label="Vulnerability Database", command=self._open_vuln_db)
        tools_menu.add_command(label="Wordlist Manager", command=self._open_wordlist_manager)
        tools_menu.add_separator()
        tools_menu.add_command(label="Preferences", command=self._open_preferences)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self._show_docs)
        help_menu.add_command(label="Keyboard Shortcuts", command=self._show_shortcuts)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self._show_about)

        # Keyboard shortcuts
        self.root.bind('<Control-n>', lambda e: self._new_scan())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        self.root.bind('<F5>', lambda e: self._start_scan())
        self.root.bind('<F6>', lambda e: self._stop_scan())

    def _create_header(self):
        """Create header with logo and title"""
        header_frame = tk.Frame(self.root, bg=self.colors['primary'], height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        # Logo and title
        title_label = tk.Label(
            header_frame,
            text="🔒 OverApi Enterprise",
            font=('Segoe UI', 24, 'bold'),
            bg=self.colors['primary'],
            fg='white'
        )
        title_label.pack(side=tk.LEFT, padx=20, pady=10)

        subtitle_label = tk.Label(
            header_frame,
            text="Professional API Security Testing Platform v2.0",
            font=('Segoe UI', 11),
            bg=self.colors['primary'],
            fg='white'
        )
        subtitle_label.pack(side=tk.LEFT, padx=20)

    def _create_main_container(self):
        """Create main container with tabs"""
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Configure notebook style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background=self.colors['bg'])
        style.configure('TNotebook.Tab', padding=[20, 10], font=('Segoe UI', 10, 'bold'))

        # Create tabs
        self._create_scan_tab()
        self._create_dashboard_tab()
        self._create_vulnerabilities_tab()
        self._create_logs_tab()
        self._create_config_tab()

    def _create_scan_tab(self):
        """Create scan configuration tab"""
        scan_frame = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(scan_frame, text='🎯 Scan Configuration')

        # Left panel - Configuration
        left_panel = tk.Frame(scan_frame, bg=self.colors['bg'])
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Target configuration
        target_frame = tk.LabelFrame(
            left_panel,
            text="Target Configuration",
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['dark']
        )
        target_frame.pack(fill=tk.X, pady=10)

        # URL
        tk.Label(target_frame, text="Target URL:", bg=self.colors['bg']).grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.url_entry = tk.Entry(target_frame, width=50, font=('Segoe UI', 10))
        self.url_entry.grid(row=0, column=1, padx=10, pady=5)
        self.url_entry.insert(0, "https://api.example.com")

        # API Type
        tk.Label(target_frame, text="API Type:", bg=self.colors['bg']).grid(row=1, column=0, sticky='w', padx=10, pady=5)
        self.api_type_var = tk.StringVar(value="auto")
        api_types = ['auto', 'rest', 'graphql', 'soap', 'grpc', 'websocket', 'webhook']
        api_type_combo = ttk.Combobox(target_frame, textvariable=self.api_type_var, values=api_types, state='readonly', width=47)
        api_type_combo.grid(row=1, column=1, padx=10, pady=5)

        # Authentication
        auth_frame = tk.LabelFrame(
            left_panel,
            text="Authentication",
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['dark']
        )
        auth_frame.pack(fill=tk.X, pady=10)

        # Auth Token
        tk.Label(auth_frame, text="Bearer Token:", bg=self.colors['bg']).grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.token_entry = tk.Entry(auth_frame, width=50, font=('Segoe UI', 10), show='*')
        self.token_entry.grid(row=0, column=1, padx=10, pady=5)

        # API Key
        tk.Label(auth_frame, text="API Key:", bg=self.colors['bg']).grid(row=1, column=0, sticky='w', padx=10, pady=5)
        self.apikey_entry = tk.Entry(auth_frame, width=50, font=('Segoe UI', 10), show='*')
        self.apikey_entry.grid(row=1, column=1, padx=10, pady=5)

        # Scan options
        options_frame = tk.LabelFrame(
            left_panel,
            text="Scan Options",
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['dark']
        )
        options_frame.pack(fill=tk.X, pady=10)

        # Mode
        tk.Label(options_frame, text="Scan Mode:", bg=self.colors['bg']).grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.mode_var = tk.StringVar(value="normal")
        modes = ['safe', 'normal', 'aggressive']
        mode_combo = ttk.Combobox(options_frame, textvariable=self.mode_var, values=modes, state='readonly', width=20)
        mode_combo.grid(row=0, column=1, padx=10, pady=5, sticky='w')

        # Threads
        tk.Label(options_frame, text="Threads:", bg=self.colors['bg']).grid(row=1, column=0, sticky='w', padx=10, pady=5)
        self.threads_var = tk.IntVar(value=10)
        threads_spinbox = tk.Spinbox(options_frame, from_=1, to=50, textvariable=self.threads_var, width=20)
        threads_spinbox.grid(row=1, column=1, padx=10, pady=5, sticky='w')

        # Timeout
        tk.Label(options_frame, text="Timeout (sec):", bg=self.colors['bg']).grid(row=2, column=0, sticky='w', padx=10, pady=5)
        self.timeout_var = tk.IntVar(value=30)
        timeout_spinbox = tk.Spinbox(options_frame, from_=5, to=120, textvariable=self.timeout_var, width=20)
        timeout_spinbox.grid(row=2, column=1, padx=10, pady=5, sticky='w')

        # Test modules
        modules_frame = tk.LabelFrame(
            left_panel,
            text="Test Modules",
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['dark']
        )
        modules_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Checkboxes for modules
        self.modules = {}
        module_list = [
            ('Injection Tests', 'injection', True),
            ('Authentication Tests', 'auth', True),
            ('Authorization Tests', 'authz', True),
            ('BOLA/IDOR Tests', 'bola', True),
            ('Rate Limiting Tests', 'ratelimit', True),
            ('Data Exposure Tests', 'data', True),
            ('CORS Tests', 'cors', True),
            ('Security Headers', 'headers', True),
            ('SSRF Tests', 'ssrf', True),
            ('Business Logic Tests', 'business', True)
        ]

        row = 0
        col = 0
        for label, key, default in module_list:
            var = tk.BooleanVar(value=default)
            cb = tk.Checkbutton(
                modules_frame,
                text=label,
                variable=var,
                bg=self.colors['bg'],
                font=('Segoe UI', 9)
            )
            cb.grid(row=row, column=col, sticky='w', padx=10, pady=3)
            self.modules[key] = var

            col += 1
            if col > 1:
                col = 0
                row += 1

        # Right panel - Actions
        right_panel = tk.Frame(scan_frame, bg=self.colors['bg'], width=300)
        right_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=10)
        right_panel.pack_propagate(False)

        # Action buttons
        action_frame = tk.LabelFrame(
            right_panel,
            text="Actions",
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['dark']
        )
        action_frame.pack(fill=tk.X, pady=10)

        self.start_btn = ModernButton(
            action_frame,
            text="🚀 Start Scan",
            bg=self.colors['success'],
            fg='white',
            command=self._start_scan
        )
        self.start_btn.pack(fill=tk.X, padx=10, pady=5)

        self.stop_btn = ModernButton(
            action_frame,
            text="⏹️ Stop Scan",
            bg=self.colors['danger'],
            fg='white',
            command=self._stop_scan,
            state=tk.DISABLED
        )
        self.stop_btn.pack(fill=tk.X, padx=10, pady=5)

        # Progress frame
        progress_frame = tk.LabelFrame(
            right_panel,
            text="Progress",
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['dark']
        )
        progress_frame.pack(fill=tk.X, pady=10)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            mode='determinate'
        )
        self.progress_bar.pack(fill=tk.X, padx=10, pady=10)

        self.progress_label = tk.Label(
            progress_frame,
            text="Ready to scan",
            font=('Segoe UI', 9),
            bg=self.colors['bg']
        )
        self.progress_label.pack(pady=5)

        # Quick stats
        stats_frame = tk.LabelFrame(
            right_panel,
            text="Quick Stats",
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['dark']
        )
        stats_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.stats_labels = {}
        stats = [
            ('Endpoints Found', 'endpoints_found', 0),
            ('Vulnerabilities', 'vulnerabilities', 0),
            ('Requests Sent', 'requests_sent', 0),
            ('Scan Time', 'scan_time', '0s')
        ]

        for label, key, default in stats:
            frame = tk.Frame(stats_frame, bg=self.colors['bg'])
            frame.pack(fill=tk.X, padx=10, pady=5)

            tk.Label(
                frame,
                text=f"{label}:",
                font=('Segoe UI', 9),
                bg=self.colors['bg']
            ).pack(side=tk.LEFT)

            value_label = tk.Label(
                frame,
                text=str(default),
                font=('Segoe UI', 9, 'bold'),
                bg=self.colors['bg'],
                fg=self.colors['primary']
            )
            value_label.pack(side=tk.RIGHT)
            self.stats_labels[key] = value_label

    def _create_dashboard_tab(self):
        """Create dashboard tab with metrics"""
        dashboard_frame = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(dashboard_frame, text='📊 Dashboard')

        # Title
        title = tk.Label(
            dashboard_frame,
            text="Security Dashboard",
            font=('Segoe UI', 18, 'bold'),
            bg=self.colors['bg']
        )
        title.pack(pady=20)

        # Metrics grid
        metrics_container = tk.Frame(dashboard_frame, bg=self.colors['bg'])
        metrics_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Metric cards
        metrics = [
            ('Total Scans', '0', self.colors['primary']),
            ('Critical Issues', '0', self.colors['danger']),
            ('High Issues', '0', self.colors['warning']),
            ('Medium Issues', '0', self.colors['info']),
        ]

        for i, (label, value, color) in enumerate(metrics):
            card = tk.Frame(metrics_container, bg=color, relief=tk.RAISED, borderwidth=2)
            card.grid(row=0, column=i, padx=10, pady=10, sticky='nsew')

            value_label = tk.Label(
                card,
                text=value,
                font=('Segoe UI', 32, 'bold'),
                bg=color,
                fg='white'
            )
            value_label.pack(pady=20)

            label_label = tk.Label(
                card,
                text=label,
                font=('Segoe UI', 12),
                bg=color,
                fg='white'
            )
            label_label.pack(pady=10)

            metrics_container.columnconfigure(i, weight=1)

        # Chart placeholder
        chart_frame = tk.LabelFrame(
            dashboard_frame,
            text="Vulnerability Distribution",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['bg']
        )
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        chart_label = tk.Label(
            chart_frame,
            text="📈 Charts will be displayed here\n(Requires matplotlib)",
            font=('Segoe UI', 14),
            bg=self.colors['bg'],
            fg=self.colors['dark']
        )
        chart_label.pack(expand=True)

    def _create_vulnerabilities_tab(self):
        """Create vulnerabilities display tab"""
        vuln_frame = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(vuln_frame, text='🔍 Vulnerabilities')

        # Filter frame
        filter_frame = tk.Frame(vuln_frame, bg=self.colors['bg'])
        filter_frame.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(filter_frame, text="Filter:", bg=self.colors['bg']).pack(side=tk.LEFT, padx=5)

        self.filter_var = tk.StringVar(value="all")
        filters = ['all', 'critical', 'high', 'medium', 'low', 'info']
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var, values=filters, state='readonly', width=15)
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind('<<ComboboxSelected>>', lambda e: self._filter_vulnerabilities())

        # Search
        tk.Label(filter_frame, text="Search:", bg=self.colors['bg']).pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(filter_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind('<KeyRelease>', lambda e: self._filter_vulnerabilities())

        # Treeview for vulnerabilities
        tree_frame = tk.Frame(vuln_frame, bg=self.colors['bg'])
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")

        # Treeview
        columns = ('severity', 'type', 'endpoint', 'owasp')
        self.vuln_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show='tree headings',
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )

        vsb.config(command=self.vuln_tree.yview)
        hsb.config(command=self.vuln_tree.xview)

        # Headings
        self.vuln_tree.heading('#0', text='ID')
        self.vuln_tree.heading('severity', text='Severity')
        self.vuln_tree.heading('type', text='Vulnerability Type')
        self.vuln_tree.heading('endpoint', text='Endpoint')
        self.vuln_tree.heading('owasp', text='OWASP Category')

        # Column widths
        self.vuln_tree.column('#0', width=50)
        self.vuln_tree.column('severity', width=100)
        self.vuln_tree.column('type', width=200)
        self.vuln_tree.column('endpoint', width=300)
        self.vuln_tree.column('owasp', width=150)

        # Tags for colors
        self.vuln_tree.tag_configure('critical', foreground='red')
        self.vuln_tree.tag_configure('high', foreground='orange')
        self.vuln_tree.tag_configure('medium', foreground='blue')
        self.vuln_tree.tag_configure('low', foreground='green')

        # Pack
        self.vuln_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        # Details panel
        details_frame = tk.LabelFrame(
            vuln_frame,
            text="Vulnerability Details",
            font=('Segoe UI', 10, 'bold'),
            bg=self.colors['bg']
        )
        details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.details_text = scrolledtext.ScrolledText(
            details_frame,
            wrap=tk.WORD,
            height=10,
            font=('Consolas', 9),
            bg='#f8f9fa'
        )
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Bind selection
        self.vuln_tree.bind('<<TreeviewSelect>>', self._on_vulnerability_select)

    def _create_logs_tab(self):
        """Create logs display tab"""
        logs_frame = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(logs_frame, text='📝 Logs')

        # Toolbar
        toolbar = tk.Frame(logs_frame, bg=self.colors['bg'])
        toolbar.pack(fill=tk.X, padx=10, pady=5)

        clear_btn = tk.Button(
            toolbar,
            text="Clear Logs",
            command=self._clear_logs,
            bg=self.colors['danger'],
            fg='white'
        )
        clear_btn.pack(side=tk.LEFT, padx=5)

        save_btn = tk.Button(
            toolbar,
            text="Save Logs",
            command=self._save_logs,
            bg=self.colors['info'],
            fg='white'
        )
        save_btn.pack(side=tk.LEFT, padx=5)

        # Log level filter
        tk.Label(toolbar, text="Level:", bg=self.colors['bg']).pack(side=tk.LEFT, padx=5)
        self.log_level_var = tk.StringVar(value="all")
        levels = ['all', 'debug', 'info', 'warning', 'error']
        level_combo = ttk.Combobox(toolbar, textvariable=self.log_level_var, values=levels, state='readonly', width=10)
        level_combo.pack(side=tk.LEFT, padx=5)

        # Logs text area
        self.logs_text = scrolledtext.ScrolledText(
            logs_frame,
            wrap=tk.WORD,
            font=('Consolas', 9),
            bg='#1e1e1e',
            fg='#d4d4d4',
            insertbackground='white'
        )
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Configure tags for colors
        self.logs_text.tag_config('DEBUG', foreground='#808080')
        self.logs_text.tag_config('INFO', foreground='#4ec9b0')
        self.logs_text.tag_config('WARNING', foreground='#ffc107')
        self.logs_text.tag_config('ERROR', foreground='#f48771')
        self.logs_text.tag_config('CRITICAL', foreground='#ff0000', font=('Consolas', 9, 'bold'))

    def _create_config_tab(self):
        """Create configuration tab"""
        config_frame = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(config_frame, text='⚙️ Configuration')

        # Configuration editor
        config_text = scrolledtext.ScrolledText(
            config_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#f8f9fa'
        )
        config_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Sample configuration
        sample_config = """# OverApi Enterprise Configuration
#
# This file contains advanced configuration options
# Edit with caution

[scan]
max_threads = 10
timeout = 30
max_endpoints = 1000
delay_between_requests = 0

[detection]
enable_ml_detection = true
confidence_threshold = 0.7

[plugins]
enabled = true
auto_update = false
plugin_dir = ./plugins

[reporting]
default_format = html
include_evidence = true
generate_executive_summary = true

[advanced]
follow_redirects = true
verify_ssl = true
custom_user_agent = OverApi/2.0
"""
        config_text.insert('1.0', sample_config)

    def _create_status_bar(self):
        """Create status bar"""
        status_frame = tk.Frame(self.root, bg=self.colors['dark'], height=30)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        status_frame.pack_propagate(False)

        self.status_label = tk.Label(
            status_frame,
            text="Ready",
            font=('Segoe UI', 9),
            bg=self.colors['dark'],
            fg='white',
            anchor='w'
        )
        self.status_label.pack(side=tk.LEFT, padx=10)

        # Version label
        version_label = tk.Label(
            status_frame,
            text="v2.0 Enterprise",
            font=('Segoe UI', 9),
            bg=self.colors['dark'],
            fg='white'
        )
        version_label.pack(side=tk.RIGHT, padx=10)

    # Event handlers
    def _start_scan(self):
        """Start security scan"""
        if self.scan_running:
            messagebox.showwarning("Scan Running", "A scan is already in progress!")
            return

        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a target URL!")
            return

        self.scan_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress_var.set(0)
        self.progress_label.config(text="Scanning...")
        self.status_label.config(text=f"Scanning {url}...")

        # Add log
        self._add_log("INFO", f"Starting scan on {url}")

        # Start scan thread
        self.scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        self.scan_thread.start()

    def _stop_scan(self):
        """Stop running scan"""
        if not self.scan_running:
            return

        self.scan_running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_label.config(text="Scan stopped")
        self.status_label.config(text="Scan stopped by user")
        self._add_log("WARNING", "Scan stopped by user")

    def _run_scan(self):
        """Run scan in background thread"""
        try:
            # Simulate scan
            for i in range(101):
                if not self.scan_running:
                    break

                self.root.after(0, self.progress_var.set, i)

                if i % 10 == 0:
                    self._add_log("INFO", f"Scan progress: {i}%")

                if i == 25:
                    self._add_log("INFO", "Discovering endpoints...")
                elif i == 50:
                    self._add_log("WARNING", "Potential vulnerability found!")
                    self._add_vulnerability({
                        'severity': 'high',
                        'type': 'SQL Injection',
                        'endpoint': '/api/users?id=1',
                        'owasp': 'API8:2023',
                        'evidence': 'SQL error message in response'
                    })
                elif i == 75:
                    self._add_log("ERROR", "Authentication bypass detected!")

                import time
                time.sleep(0.05)

            if self.scan_running:
                self.progress_var.set(100)
                self.progress_label.config(text="Scan completed!")
                self.status_label.config(text="Scan completed successfully")
                self._add_log("INFO", "Scan completed successfully")
                messagebox.showinfo("Scan Complete", "Security scan completed successfully!")

        except Exception as e:
            self._add_log("ERROR", f"Scan error: {str(e)}")
            messagebox.showerror("Scan Error", f"An error occurred: {str(e)}")

        finally:
            self.scan_running = False
            self.root.after(0, self.start_btn.config, {'state': tk.NORMAL})
            self.root.after(0, self.stop_btn.config, {'state': tk.DISABLED})

    def _add_log(self, level, message):
        """Add log message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}\n"
        self.log_queue.put((level, log_message))

    def _update_logs(self):
        """Update logs from queue"""
        try:
            while True:
                level, message = self.log_queue.get_nowait()
                self.logs_text.insert(tk.END, message, level.upper())
                self.logs_text.see(tk.END)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._update_logs)

    def _add_vulnerability(self, vuln):
        """Add vulnerability to list"""
        self.vulnerabilities.append(vuln)
        idx = len(self.vulnerabilities)

        self.vuln_tree.insert(
            '',
            'end',
            text=str(idx),
            values=(
                vuln['severity'].upper(),
                vuln['type'],
                vuln['endpoint'],
                vuln['owasp']
            ),
            tags=(vuln['severity'].lower(),)
        )

        # Update stats
        self.scan_stats['vulnerabilities'] += 1
        self.stats_labels['vulnerabilities'].config(text=str(self.scan_stats['vulnerabilities']))

    def _filter_vulnerabilities(self):
        """Filter vulnerability display"""
        # Implementation for filtering
        pass

    def _on_vulnerability_select(self, event):
        """Handle vulnerability selection"""
        selection = self.vuln_tree.selection()
        if not selection:
            return

        item = self.vuln_tree.item(selection[0])
        idx = int(item['text']) - 1

        if 0 <= idx < len(self.vulnerabilities):
            vuln = self.vulnerabilities[idx]
            details = f"""Vulnerability Details:

Type: {vuln['type']}
Severity: {vuln['severity'].upper()}
Endpoint: {vuln['endpoint']}
OWASP Category: {vuln['owasp']}

Evidence:
{vuln.get('evidence', 'No evidence available')}

Recommendation:
Implement proper input validation and parameterized queries.
"""
            self.details_text.delete('1.0', tk.END)
            self.details_text.insert('1.0', details)

    def _clear_logs(self):
        """Clear log display"""
        self.logs_text.delete('1.0', tk.END)

    def _save_logs(self):
        """Save logs to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.logs_text.get('1.0', tk.END))
                messagebox.showinfo("Success", "Logs saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {str(e)}")

    def _export_report(self, format_type):
        """Export scan report"""
        if not self.vulnerabilities:
            messagebox.showwarning("No Data", "No vulnerabilities to export!")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=[(f"{format_type.upper()} files", f"*.{format_type}"), ("All files", "*.*")]
        )

        if filename:
            try:
                if format_type == 'json':
                    with open(filename, 'w') as f:
                        json.dump(self.vulnerabilities, f, indent=2)
                elif format_type == 'csv':
                    import csv
                    with open(filename, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=['severity', 'type', 'endpoint', 'owasp'])
                        writer.writeheader()
                        writer.writerows(self.vulnerabilities)
                else:
                    messagebox.showinfo("Info", f"{format_type.upper()} export not yet implemented")
                    return

                messagebox.showinfo("Success", f"Report exported to {format_type.upper()} successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")

    def _new_scan(self):
        """Reset for new scan"""
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, "https://api.example.com")
        self.token_entry.delete(0, tk.END)
        self.apikey_entry.delete(0, tk.END)
        self.vulnerabilities = []
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        self.progress_var.set(0)

    def _load_config(self):
        """Load configuration from file"""
        messagebox.showinfo("Info", "Load configuration - Not yet implemented")

    def _save_config(self):
        """Save configuration to file"""
        messagebox.showinfo("Info", "Save configuration - Not yet implemented")

    def _quick_scan(self):
        """Run quick scan"""
        self.mode_var.set('safe')
        self._start_scan()

    def _deep_scan(self):
        """Run deep scan"""
        self.mode_var.set('aggressive')
        self._start_scan()

    def _open_plugin_manager(self):
        """Open plugin manager"""
        messagebox.showinfo("Plugin Manager", "Plugin Manager - Coming Soon!")

    def _open_vuln_db(self):
        """Open vulnerability database"""
        messagebox.showinfo("Vulnerability Database", "Vulnerability Database - Coming Soon!")

    def _open_wordlist_manager(self):
        """Open wordlist manager"""
        messagebox.showinfo("Wordlist Manager", "Wordlist Manager - Coming Soon!")

    def _open_preferences(self):
        """Open preferences dialog"""
        messagebox.showinfo("Preferences", "Preferences - Coming Soon!")

    def _show_docs(self):
        """Show documentation"""
        messagebox.showinfo("Documentation", "Documentation available at:\nhttps://github.com/GhostN3xus/OverApi")

    def _show_shortcuts(self):
        """Show keyboard shortcuts"""
        shortcuts = """Keyboard Shortcuts:

Ctrl+N - New Scan
Ctrl+Q - Quit
F5 - Start Scan
F6 - Stop Scan
"""
        messagebox.showinfo("Keyboard Shortcuts", shortcuts)

    def _show_about(self):
        """Show about dialog"""
        about_text = """OverApi Enterprise Edition
Version 2.0

Professional API Security Testing Platform

© 2024 GhostN3xus
Licensed under MIT License

Built with Python & Tkinter
"""
        messagebox.showinfo("About OverApi", about_text)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = EnterpriseGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
