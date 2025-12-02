#!/usr/bin/env python3
"""
OverApi GUI - Interface Gráfica para OverApi
Ferramenta profissional de testes de segurança em APIs
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import subprocess
import sys
import os
from pathlib import Path


class OverApiGUI:
    """Interface gráfica principal do OverApi"""

    def __init__(self, root):
        self.root = root
        self.root.title("🔒 OverApi - Universal API Security Scanner")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)

        # Variáveis
        self.running = False
        self.process = None

        # Configurar estilo
        self.setup_style()

        # Criar interface
        self.create_widgets()

    def setup_style(self):
        """Configurar estilo da interface"""
        style = ttk.Style()
        style.theme_use('clam')

        # Cores
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground='#2c3e50')
        style.configure('Header.TLabel', font=('Arial', 10, 'bold'), foreground='#34495e')
        style.configure('TButton', font=('Arial', 9))
        style.configure('Action.TButton', font=('Arial', 10, 'bold'))

    def create_widgets(self):
        """Criar todos os widgets da interface"""

        # Frame principal com scroll
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configurar grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        # Título
        title_label = ttk.Label(main_frame, text="🔒 OverApi - Universal API Security Scanner",
                               style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        # Notebook (Tabs)
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        main_frame.rowconfigure(1, weight=1)

        # Tab 1: Configuração Básica
        basic_frame = ttk.Frame(notebook, padding="10")
        notebook.add(basic_frame, text="⚙️ Configuração Básica")
        self.create_basic_tab(basic_frame)

        # Tab 2: Autenticação
        auth_frame = ttk.Frame(notebook, padding="10")
        notebook.add(auth_frame, text="🔑 Autenticação")
        self.create_auth_tab(auth_frame)

        # Tab 3: Avançado
        advanced_frame = ttk.Frame(notebook, padding="10")
        notebook.add(advanced_frame, text="🔧 Avançado")
        self.create_advanced_tab(advanced_frame)

        # Tab 4: Módulos de Teste
        modules_frame = ttk.Frame(notebook, padding="10")
        notebook.add(modules_frame, text="🧪 Módulos de Teste")
        self.create_modules_tab(modules_frame)

        # Área de Output
        output_frame = ttk.LabelFrame(main_frame, text="📊 Output / Logs", padding="10")
        output_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 10))
        main_frame.rowconfigure(2, weight=1)

        self.output_text = scrolledtext.ScrolledText(output_frame, height=12, wrap=tk.WORD,
                                                     font=('Courier', 9))
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)

        # Botões de ação
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=3, column=0, columnspan=2, pady=(10, 0))

        self.start_button = ttk.Button(action_frame, text="▶️ Iniciar Scan",
                                       command=self.start_scan, style='Action.TButton')
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = ttk.Button(action_frame, text="⏹️ Parar Scan",
                                      command=self.stop_scan, state=tk.DISABLED,
                                      style='Action.TButton')
        self.stop_button.grid(row=0, column=1, padx=5)

        self.clear_button = ttk.Button(action_frame, text="🗑️ Limpar Output",
                                       command=self.clear_output)
        self.clear_button.grid(row=0, column=2, padx=5)

        # Barra de status
        self.status_var = tk.StringVar(value="✅ Pronto")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var,
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

    def create_basic_tab(self, parent):
        """Criar tab de configuração básica"""

        # URL
        ttk.Label(parent, text="🎯 URL da API:", style='Header.TLabel').grid(
            row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(parent, textvariable=self.url_var, width=60)
        url_entry.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        parent.columnconfigure(0, weight=1)

        # Tipo de API
        ttk.Label(parent, text="📡 Tipo de API:", style='Header.TLabel').grid(
            row=2, column=0, sticky=tk.W, pady=(0, 5))
        self.api_type_var = tk.StringVar(value="auto")
        api_type_combo = ttk.Combobox(parent, textvariable=self.api_type_var,
                                      values=["auto", "rest", "graphql", "soap", "grpc",
                                             "websocket", "webhook"],
                                      state="readonly", width=20)
        api_type_combo.grid(row=3, column=0, sticky=tk.W, pady=(0, 15))

        # Modo de Scan
        ttk.Label(parent, text="⚡ Modo de Scan:", style='Header.TLabel').grid(
            row=4, column=0, sticky=tk.W, pady=(0, 5))
        self.mode_var = tk.StringVar(value="normal")

        mode_frame = ttk.Frame(parent)
        mode_frame.grid(row=5, column=0, sticky=tk.W, pady=(0, 15))

        ttk.Radiobutton(mode_frame, text="🛡️ Safe (Passivo)",
                       variable=self.mode_var, value="safe").grid(row=0, column=0, padx=(0, 10))
        ttk.Radiobutton(mode_frame, text="⚖️ Normal (Recomendado)",
                       variable=self.mode_var, value="normal").grid(row=0, column=1, padx=(0, 10))
        ttk.Radiobutton(mode_frame, text="🔥 Aggressive (Intensivo)",
                       variable=self.mode_var, value="aggressive").grid(row=0, column=2)

        # Threads
        ttk.Label(parent, text="🧵 Threads:", style='Header.TLabel').grid(
            row=6, column=0, sticky=tk.W, pady=(0, 5))
        self.threads_var = tk.IntVar(value=10)
        threads_frame = ttk.Frame(parent)
        threads_frame.grid(row=7, column=0, sticky=tk.W, pady=(0, 15))

        ttk.Scale(threads_frame, from_=1, to=50, variable=self.threads_var,
                 orient=tk.HORIZONTAL, length=300).grid(row=0, column=0, padx=(0, 10))
        ttk.Label(threads_frame, textvariable=self.threads_var).grid(row=0, column=1)

        # Timeout
        ttk.Label(parent, text="⏱️ Timeout (segundos):", style='Header.TLabel').grid(
            row=8, column=0, sticky=tk.W, pady=(0, 5))
        self.timeout_var = tk.IntVar(value=30)
        timeout_spin = ttk.Spinbox(parent, from_=5, to=300, textvariable=self.timeout_var,
                                   width=10)
        timeout_spin.grid(row=9, column=0, sticky=tk.W, pady=(0, 15))

        # Relatórios
        ttk.Label(parent, text="📊 Relatórios:", style='Header.TLabel').grid(
            row=10, column=0, sticky=tk.W, pady=(0, 5))

        report_frame = ttk.Frame(parent)
        report_frame.grid(row=11, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))

        # HTML Report
        self.html_report_var = tk.StringVar()
        ttk.Label(report_frame, text="HTML:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(report_frame, textvariable=self.html_report_var, width=40).grid(
            row=0, column=1, padx=(5, 5))
        ttk.Button(report_frame, text="📂", command=lambda: self.browse_file(self.html_report_var,
                  "HTML", ".html")).grid(row=0, column=2)

        # JSON Report
        self.json_report_var = tk.StringVar()
        ttk.Label(report_frame, text="JSON:").grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        ttk.Entry(report_frame, textvariable=self.json_report_var, width=40).grid(
            row=1, column=1, padx=(5, 5), pady=(5, 0))
        ttk.Button(report_frame, text="📂", command=lambda: self.browse_file(self.json_report_var,
                  "JSON", ".json")).grid(row=1, column=2, pady=(5, 0))

    def create_auth_tab(self, parent):
        """Criar tab de autenticação"""

        # Auth Token
        ttk.Label(parent, text="🔑 Token de Autenticação (Bearer):", style='Header.TLabel').grid(
            row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.auth_token_var = tk.StringVar()
        auth_entry = ttk.Entry(parent, textvariable=self.auth_token_var, width=60, show="*")
        auth_entry.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        parent.columnconfigure(0, weight=1)

        # Custom Headers
        ttk.Label(parent, text="📋 Headers Customizados:", style='Header.TLabel').grid(
            row=2, column=0, sticky=tk.W, pady=(0, 5))
        ttk.Label(parent, text="(Um por linha, formato: Key: Value)",
                 font=('Arial', 8, 'italic')).grid(row=3, column=0, sticky=tk.W, pady=(0, 5))

        self.headers_text = scrolledtext.ScrolledText(parent, height=6, width=60,
                                                      font=('Courier', 9))
        self.headers_text.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        self.headers_text.insert('1.0', "# Exemplo:\n# X-API-Key: sua-chave-aqui\n# Custom-Header: valor")

        # Cookie
        ttk.Label(parent, text="🍪 Cookie:", style='Header.TLabel').grid(
            row=5, column=0, sticky=tk.W, pady=(0, 5))
        self.cookie_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.cookie_var, width=60).grid(
            row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))

        # User-Agent
        ttk.Label(parent, text="🌐 User-Agent:", style='Header.TLabel').grid(
            row=7, column=0, sticky=tk.W, pady=(0, 5))
        self.user_agent_var = tk.StringVar(value="OverApi/1.0")
        ttk.Entry(parent, textvariable=self.user_agent_var, width=60).grid(
            row=8, column=0, columnspan=2, sticky=(tk.W, tk.E))

    def create_advanced_tab(self, parent):
        """Criar tab de configurações avançadas"""

        # Proxy
        ttk.Label(parent, text="🔄 Proxy (http://ip:port):", style='Header.TLabel').grid(
            row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.proxy_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.proxy_var, width=60).grid(
            row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        parent.columnconfigure(0, weight=1)

        # SSL
        self.verify_ssl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text="🔒 Verificar certificados SSL (recomendado)",
                       variable=self.verify_ssl_var).grid(row=2, column=0, sticky=tk.W, pady=(0, 15))

        # Wordlist
        ttk.Label(parent, text="📚 Wordlist Customizada:", style='Header.TLabel').grid(
            row=3, column=0, sticky=tk.W, pady=(0, 5))

        wordlist_frame = ttk.Frame(parent)
        wordlist_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))

        self.wordlist_var = tk.StringVar()
        ttk.Entry(wordlist_frame, textvariable=self.wordlist_var, width=50).grid(
            row=0, column=0, sticky=(tk.W, tk.E))
        ttk.Button(wordlist_frame, text="📂 Procurar",
                  command=lambda: self.browse_file(self.wordlist_var, "Text", ".txt",
                  save=False)).grid(row=0, column=1, padx=(5, 0))
        wordlist_frame.columnconfigure(0, weight=1)

        # Max Endpoints
        ttk.Label(parent, text="🎯 Máximo de Endpoints:", style='Header.TLabel').grid(
            row=5, column=0, sticky=tk.W, pady=(0, 5))
        self.max_endpoints_var = tk.IntVar(value=1000)
        ttk.Spinbox(parent, from_=10, to=10000, textvariable=self.max_endpoints_var,
                   width=15).grid(row=6, column=0, sticky=tk.W, pady=(0, 15))

        # Delay
        ttk.Label(parent, text="⏳ Delay entre requisições (segundos):",
                 style='Header.TLabel').grid(row=7, column=0, sticky=tk.W, pady=(0, 5))
        self.delay_var = tk.DoubleVar(value=0)
        ttk.Spinbox(parent, from_=0, to=10, increment=0.1, textvariable=self.delay_var,
                   width=15).grid(row=8, column=0, sticky=tk.W, pady=(0, 15))

        # Verbose
        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, text="📢 Modo Verbose (output detalhado)",
                       variable=self.verbose_var).grid(row=9, column=0, sticky=tk.W, pady=(0, 5))

        # Quiet
        self.quiet_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, text="🔇 Modo Silencioso (output mínimo)",
                       variable=self.quiet_var).grid(row=10, column=0, sticky=tk.W)

    def create_modules_tab(self, parent):
        """Criar tab de módulos de teste"""

        ttk.Label(parent, text="Selecione os módulos de teste a serem executados:",
                 style='Header.TLabel').grid(row=0, column=0, sticky=tk.W, pady=(0, 15))
        parent.columnconfigure(0, weight=1)

        # Checkboxes para módulos
        self.fuzzing_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text="🔍 Fuzzing / Descoberta de Endpoints",
                       variable=self.fuzzing_var).grid(row=1, column=0, sticky=tk.W, pady=(0, 5))

        self.injection_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text="💉 Testes de Injeção (SQLi, XSS, NoSQL, etc.)",
                       variable=self.injection_var).grid(row=2, column=0, sticky=tk.W, pady=(0, 5))

        self.ratelimit_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text="⏱️ Testes de Rate Limit",
                       variable=self.ratelimit_var).grid(row=3, column=0, sticky=tk.W, pady=(0, 5))

        self.bola_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text="🔓 Testes BOLA (Broken Object Level Authorization)",
                       variable=self.bola_var).grid(row=4, column=0, sticky=tk.W, pady=(0, 5))

        self.auth_bypass_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text="🚪 Testes de Bypass de Autenticação",
                       variable=self.auth_bypass_var).grid(row=5, column=0, sticky=tk.W, pady=(0, 15))

        ttk.Label(parent, text="ℹ️ Dica: Desabilite módulos específicos para scans mais rápidos",
                 font=('Arial', 8, 'italic')).grid(row=6, column=0, sticky=tk.W)

    def browse_file(self, var, file_type, extension, save=True):
        """Abrir diálogo para selecionar arquivo"""
        if save:
            filename = filedialog.asksaveasfilename(
                defaultextension=extension,
                filetypes=[(f"{file_type} files", f"*{extension}"), ("All files", "*.*")]
            )
        else:
            filename = filedialog.askopenfilename(
                filetypes=[(f"{file_type} files", f"*{extension}"), ("All files", "*.*")]
            )

        if filename:
            var.set(filename)

    def build_command(self):
        """Construir comando overapi com base nas configurações"""

        # Validar URL
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Erro", "Por favor, informe a URL da API!")
            return None

        # Comando base
        cmd = ["overapi", "scan", "--url", url]

        # Tipo de API
        if self.api_type_var.get() != "auto":
            cmd.extend(["--type", self.api_type_var.get()])

        # Modo
        cmd.extend(["--mode", self.mode_var.get()])

        # Threads
        cmd.extend(["--threads", str(self.threads_var.get())])

        # Timeout
        cmd.extend(["--timeout", str(self.timeout_var.get())])

        # Autenticação
        if self.auth_token_var.get().strip():
            cmd.extend(["--auth-token", self.auth_token_var.get().strip()])

        # Headers customizados
        headers = self.headers_text.get('1.0', tk.END).strip()
        if headers:
            for line in headers.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    cmd.extend(["--header", line])

        # Cookie
        if self.cookie_var.get().strip():
            cmd.extend(["--cookie", self.cookie_var.get().strip()])

        # User-Agent
        if self.user_agent_var.get().strip() != "OverApi/1.0":
            cmd.extend(["--user-agent", self.user_agent_var.get().strip()])

        # Proxy
        if self.proxy_var.get().strip():
            cmd.extend(["--proxy", self.proxy_var.get().strip()])

        # SSL
        if not self.verify_ssl_var.get():
            cmd.append("--no-verify-ssl")

        # Wordlist
        if self.wordlist_var.get().strip():
            cmd.extend(["--wordlist", self.wordlist_var.get().strip()])

        # Max endpoints
        if self.max_endpoints_var.get() != 1000:
            cmd.extend(["--max-endpoints", str(self.max_endpoints_var.get())])

        # Delay
        if self.delay_var.get() > 0:
            cmd.extend(["--delay", str(self.delay_var.get())])

        # Módulos
        if not self.fuzzing_var.get():
            cmd.append("--no-fuzzing")
        if not self.injection_var.get():
            cmd.append("--no-injection")
        if not self.ratelimit_var.get():
            cmd.append("--no-ratelimit")
        if not self.bola_var.get():
            cmd.append("--no-bola")
        if not self.auth_bypass_var.get():
            cmd.append("--no-auth-bypass")

        # Relatórios
        if self.html_report_var.get().strip():
            cmd.extend(["--out", self.html_report_var.get().strip()])
        if self.json_report_var.get().strip():
            cmd.extend(["--json", self.json_report_var.get().strip()])

        # Verbose/Quiet
        if self.verbose_var.get():
            cmd.append("--verbose")
        elif self.quiet_var.get():
            cmd.append("--quiet")

        return cmd

    def start_scan(self):
        """Iniciar scan em thread separada"""

        cmd = self.build_command()
        if not cmd:
            return

        # Limpar output
        self.output_text.delete('1.0', tk.END)
        self.log_output(f"🚀 Iniciando scan...\n")
        self.log_output(f"📝 Comando: {' '.join(cmd)}\n\n")

        # Desabilitar botão de início
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.running = True
        self.status_var.set("⚡ Executando scan...")

        # Executar em thread
        thread = threading.Thread(target=self.run_scan, args=(cmd,), daemon=True)
        thread.start()

    def run_scan(self, cmd):
        """Executar o scan"""
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            # Ler output em tempo real
            for line in self.process.stdout:
                if not self.running:
                    break
                self.log_output(line)

            # Esperar processo terminar
            self.process.wait()

            if self.running:
                if self.process.returncode == 0:
                    self.log_output("\n✅ Scan concluído com sucesso!\n")
                    self.status_var.set("✅ Scan concluído!")
                else:
                    self.log_output(f"\n❌ Scan finalizado com código de erro: {self.process.returncode}\n")
                    self.status_var.set("❌ Erro no scan")

        except Exception as e:
            self.log_output(f"\n❌ Erro ao executar scan: {str(e)}\n")
            self.status_var.set("❌ Erro")

        finally:
            self.running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def stop_scan(self):
        """Parar scan em execução"""
        if self.process and self.running:
            self.running = False
            self.process.terminate()
            self.log_output("\n⏹️ Scan interrompido pelo usuário\n")
            self.status_var.set("⏹️ Scan interrompido")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def clear_output(self):
        """Limpar área de output"""
        self.output_text.delete('1.0', tk.END)
        self.status_var.set("✅ Output limpo")

    def log_output(self, text):
        """Adicionar texto ao output"""
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.update()


def main():
    """Função principal"""
    root = tk.Tk()
    app = OverApiGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
