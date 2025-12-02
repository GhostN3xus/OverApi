#!/bin/bash

################################################################################
# OverApi - Script de Instalação Automatizada
# Universal API Security Scanner
#
# Este script instala o OverApi e todas as suas dependências
# Suporta múltiplos modos de instalação
################################################################################

set -e  # Sair em caso de erro

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Símbolos
CHECK="${GREEN}✓${NC}"
CROSS="${RED}✗${NC}"
INFO="${BLUE}ℹ${NC}"
WARN="${YELLOW}⚠${NC}"

################################################################################
# Funções Auxiliares
################################################################################

print_banner() {
    echo -e "${PURPLE}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🔒 OverApi - Universal API Security Scanner            ║
║                                                           ║
║   Script de Instalação Automatizada                      ║
║   Versão: 1.0.0                                          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_success() {
    echo -e "  ${CHECK} $1"
}

print_error() {
    echo -e "  ${CROSS} $1"
}

print_info() {
    echo -e "  ${INFO} $1"
}

print_warn() {
    echo -e "  ${WARN} $1"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

################################################################################
# Verificação de Requisitos
################################################################################

check_requirements() {
    print_section "📋 Verificando Requisitos"

    local all_ok=true

    # Python 3
    if check_command python3; then
        PYTHON_VERSION=$(python3 --version | awk '{print $2}')
        print_success "Python 3 encontrado: ${PYTHON_VERSION}"
        PYTHON_CMD="python3"
    elif check_command python; then
        PYTHON_VERSION=$(python --version | awk '{print $2}')
        if [[ $PYTHON_VERSION == 3* ]]; then
            print_success "Python 3 encontrado: ${PYTHON_VERSION}"
            PYTHON_CMD="python"
        else
            print_error "Python 3 não encontrado (versão atual: ${PYTHON_VERSION})"
            all_ok=false
        fi
    else
        print_error "Python 3 não encontrado"
        all_ok=false
    fi

    # Verificar versão mínima do Python (3.8+)
    if [ "$all_ok" = true ]; then
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

        if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
            print_error "Python 3.8+ é necessário (versão atual: ${PYTHON_VERSION})"
            all_ok=false
        fi
    fi

    # pip
    if check_command pip3; then
        print_success "pip3 encontrado"
        PIP_CMD="pip3"
    elif check_command pip; then
        print_success "pip encontrado"
        PIP_CMD="pip"
    else
        print_warn "pip não encontrado - será instalado"
        PIP_CMD=""
    fi

    # Git
    if check_command git; then
        print_success "Git encontrado"
    else
        print_warn "Git não encontrado (necessário para clonar repositório)"
    fi

    # tkinter (para GUI)
    if $PYTHON_CMD -c "import tkinter" &> /dev/null; then
        print_success "tkinter encontrado (GUI disponível)"
    else
        print_warn "tkinter não encontrado (GUI não estará disponível)"
        print_info "Instale com: apt-get install python3-tk (Ubuntu/Debian)"
    fi

    if [ "$all_ok" = false ]; then
        echo ""
        print_error "Alguns requisitos não foram atendidos"
        echo -e "\n${YELLOW}Instale os requisitos necessários:${NC}"
        echo -e "  Ubuntu/Debian: ${CYAN}sudo apt-get install python3 python3-pip python3-tk${NC}"
        echo -e "  Fedora/RHEL:   ${CYAN}sudo dnf install python3 python3-pip python3-tkinter${NC}"
        echo -e "  macOS:         ${CYAN}brew install python3 python-tk${NC}"
        exit 1
    fi

    echo ""
}

################################################################################
# Instalação do pip
################################################################################

install_pip() {
    if [ -z "$PIP_CMD" ]; then
        print_section "📦 Instalando pip"

        if check_command curl; then
            curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
            $PYTHON_CMD /tmp/get-pip.py --user
            rm /tmp/get-pip.py
        elif check_command wget; then
            wget -q https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py
            $PYTHON_CMD /tmp/get-pip.py --user
            rm /tmp/get-pip.py
        else
            print_error "curl ou wget necessário para instalar pip"
            exit 1
        fi

        # Atualizar PIP_CMD
        if check_command pip3; then
            PIP_CMD="pip3"
        elif check_command pip; then
            PIP_CMD="pip"
        else
            print_error "Falha ao instalar pip"
            exit 1
        fi

        print_success "pip instalado com sucesso"
        echo ""
    fi
}

################################################################################
# Seleção do Modo de Instalação
################################################################################

select_install_mode() {
    print_section "⚙️ Modo de Instalação"

    echo -e "${CYAN}Selecione o modo de instalação:${NC}\n"
    echo -e "  ${GREEN}1)${NC} Instalação Global (recomendado)"
    echo -e "     → Instala no sistema, comando 'overapi' disponível globalmente"
    echo -e ""
    echo -e "  ${GREEN}2)${NC} Ambiente Virtual (desenvolvimento)"
    echo -e "     → Cria venv isolado, ideal para desenvolvimento"
    echo -e ""
    echo -e "  ${GREEN}3)${NC} Instalação Local (sem pip install)"
    echo -e "     → Apenas instala dependências, usa python -m overapi"
    echo -e ""

    read -p "$(echo -e ${YELLOW}Escolha [1-3]: ${NC})" choice

    case $choice in
        1)
            INSTALL_MODE="global"
            print_info "Modo selecionado: Instalação Global"
            ;;
        2)
            INSTALL_MODE="venv"
            print_info "Modo selecionado: Ambiente Virtual"
            ;;
        3)
            INSTALL_MODE="local"
            print_info "Modo selecionado: Instalação Local"
            ;;
        *)
            print_error "Opção inválida"
            exit 1
            ;;
    esac

    echo ""
}

################################################################################
# Instalação Global
################################################################################

install_global() {
    print_section "🌍 Instalação Global"

    print_info "Atualizando pip..."
    $PIP_CMD install --upgrade pip

    print_info "Instalando OverApi..."
    $PIP_CMD install -e .

    print_success "OverApi instalado com sucesso!"

    echo ""
    print_info "Testando instalação..."
    if overapi --version &> /dev/null; then
        print_success "Comando 'overapi' disponível"
    else
        print_warn "Comando 'overapi' não encontrado no PATH"
        print_info "Adicione ~/.local/bin ao PATH:"
        echo -e "  ${CYAN}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    fi
}

################################################################################
# Instalação com Ambiente Virtual
################################################################################

install_venv() {
    print_section "🔧 Criando Ambiente Virtual"

    VENV_DIR="venv"

    if [ -d "$VENV_DIR" ]; then
        print_warn "Ambiente virtual já existe"
        read -p "$(echo -e ${YELLOW}Deseja recriá-lo? [s/N]: ${NC})" recreate
        if [[ $recreate =~ ^[Ss]$ ]]; then
            print_info "Removendo ambiente virtual antigo..."
            rm -rf "$VENV_DIR"
        else
            print_info "Usando ambiente virtual existente"
        fi
    fi

    if [ ! -d "$VENV_DIR" ]; then
        print_info "Criando ambiente virtual..."
        $PYTHON_CMD -m venv "$VENV_DIR"
        print_success "Ambiente virtual criado"
    fi

    print_info "Ativando ambiente virtual..."
    source "$VENV_DIR/bin/activate"

    print_info "Atualizando pip..."
    pip install --upgrade pip

    print_info "Instalando OverApi..."
    pip install -e .

    print_success "OverApi instalado no ambiente virtual!"

    echo ""
    print_info "Para usar o OverApi:"
    echo -e "  ${CYAN}source venv/bin/activate${NC}"
    echo -e "  ${CYAN}overapi --version${NC}"
}

################################################################################
# Instalação Local
################################################################################

install_local() {
    print_section "📂 Instalação Local"

    print_info "Atualizando pip..."
    $PIP_CMD install --upgrade pip

    print_info "Instalando dependências..."
    $PIP_CMD install -r requirements.txt

    print_success "Dependências instaladas!"

    echo ""
    print_info "Para usar o OverApi:"
    echo -e "  ${CYAN}python -m overapi --version${NC}"
    echo -e "  ${CYAN}python -m overapi scan --url https://api.example.com${NC}"
}

################################################################################
# Instalação de Ferramentas Adicionais
################################################################################

install_additional_tools() {
    print_section "🛠️ Ferramentas Adicionais"

    echo -e "${CYAN}Deseja instalar ferramentas adicionais?${NC}\n"
    echo -e "  - SecLists (wordlists para fuzzing)"
    echo -e "  - Ferramentas de pentest úteis"
    echo ""

    read -p "$(echo -e ${YELLOW}Instalar ferramentas adicionais? [s/N]: ${NC})" install_tools

    if [[ $install_tools =~ ^[Ss]$ ]]; then
        print_info "Instalando SecLists..."

        if [ -d "/usr/share/seclists" ]; then
            print_success "SecLists já instalado"
        elif [ -d "$HOME/seclists" ]; then
            print_success "SecLists já instalado em $HOME/seclists"
        else
            print_info "Clonando SecLists..."
            git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$HOME/seclists"
            print_success "SecLists instalado em $HOME/seclists"
        fi

        echo ""
    fi
}

################################################################################
# Verificação Pós-Instalação
################################################################################

post_install_check() {
    print_section "✅ Verificação Pós-Instalação"

    # Verificar instalação
    if [ "$INSTALL_MODE" = "global" ]; then
        if overapi --version &> /dev/null; then
            print_success "OverApi instalado corretamente"
            OVERAPI_VERSION=$(overapi --version 2>&1 | grep -oP '\d+\.\d+\.\d+' || echo "unknown")
            print_info "Versão: ${OVERAPI_VERSION}"
        else
            print_error "Erro ao verificar instalação"
        fi
    elif [ "$INSTALL_MODE" = "local" ]; then
        if $PYTHON_CMD -m overapi --version &> /dev/null; then
            print_success "OverApi instalado corretamente"
        else
            print_error "Erro ao verificar instalação"
        fi
    else
        print_success "OverApi instalado no ambiente virtual"
    fi

    echo ""
}

################################################################################
# Exemplos de Uso
################################################################################

show_usage_examples() {
    print_section "📚 Exemplos de Uso"

    echo -e "${CYAN}Comandos básicos:${NC}\n"

    if [ "$INSTALL_MODE" = "global" ]; then
        echo -e "  ${GREEN}# Ver ajuda${NC}"
        echo -e "  ${CYAN}overapi --help${NC}\n"

        echo -e "  ${GREEN}# Escanear API${NC}"
        echo -e "  ${CYAN}overapi scan --url https://api.example.com${NC}\n"

        echo -e "  ${GREEN}# Abrir GUI${NC}"
        echo -e "  ${CYAN}overapi-gui${NC}\n"

        echo -e "  ${GREEN}# Scan com relatório${NC}"
        echo -e "  ${CYAN}overapi scan --url https://api.example.com --out report.html${NC}\n"
    elif [ "$INSTALL_MODE" = "local" ]; then
        echo -e "  ${GREEN}# Ver ajuda${NC}"
        echo -e "  ${CYAN}python -m overapi --help${NC}\n"

        echo -e "  ${GREEN}# Escanear API${NC}"
        echo -e "  ${CYAN}python -m overapi scan --url https://api.example.com${NC}\n"

        echo -e "  ${GREEN}# Abrir GUI${NC}"
        echo -e "  ${CYAN}python -m overapi.gui${NC}\n"
    else
        echo -e "  ${GREEN}# Ativar ambiente virtual${NC}"
        echo -e "  ${CYAN}source venv/bin/activate${NC}\n"

        echo -e "  ${GREEN}# Ver ajuda${NC}"
        echo -e "  ${CYAN}overapi --help${NC}\n"

        echo -e "  ${GREEN}# Escanear API${NC}"
        echo -e "  ${CYAN}overapi scan --url https://api.example.com${NC}\n"
    fi

    echo -e "${YELLOW}📖 Documentação completa: README.md${NC}"
    echo ""
}

################################################################################
# Criar atalhos
################################################################################

create_shortcuts() {
    if [ "$INSTALL_MODE" = "global" ]; then
        print_section "🔗 Criando Atalhos"

        # Criar comando overapi-gui
        local bin_dir="$HOME/.local/bin"
        mkdir -p "$bin_dir"

        cat > "$bin_dir/overapi-gui" << 'EOF'
#!/usr/bin/env python3
from overapi.gui import main
if __name__ == "__main__":
    main()
EOF

        chmod +x "$bin_dir/overapi-gui"
        print_success "Atalho 'overapi-gui' criado"

        # Verificar se está no PATH
        if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
            print_warn "$bin_dir não está no PATH"
            print_info "Adicione ao seu ~/.bashrc ou ~/.zshrc:"
            echo -e "  ${CYAN}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
        fi

        echo ""
    fi
}

################################################################################
# Main
################################################################################

main() {
    print_banner

    # Verificar se está no diretório correto
    if [ ! -f "setup.py" ] || [ ! -d "overapi" ]; then
        print_error "Execute este script no diretório raiz do OverApi"
        exit 1
    fi

    check_requirements
    install_pip
    select_install_mode

    case $INSTALL_MODE in
        global)
            install_global
            create_shortcuts
            ;;
        venv)
            install_venv
            ;;
        local)
            install_local
            ;;
    esac

    install_additional_tools
    post_install_check
    show_usage_examples

    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                           ║${NC}"
    echo -e "${GREEN}║  ✅ Instalação Concluída com Sucesso!                    ║${NC}"
    echo -e "${GREEN}║                                                           ║${NC}"
    echo -e "${GREEN}║  Agora você pode usar o OverApi para testar APIs         ║${NC}"
    echo -e "${GREEN}║                                                           ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Executar
main
