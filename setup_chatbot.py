#!/usr/bin/env python3
"""
VEX Chatbot Setup Script - Automated setup for the VEX data chatbot
"""

import os
import sys
import subprocess
import platform
import urllib.request
import json
from pathlib import Path

def run_command(command, check=True):
    """Run a shell command and return the result"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=check)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, e.stdout, e.stderr

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8 or higher is required")
        print(f"Current version: {version.major}.{version.minor}.{version.micro}")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} is compatible")
    return True

def check_virtual_env():
    """Check if we're in a virtual environment"""
    in_venv = sys.prefix != sys.base_prefix
    if in_venv:
        print(f"✅ Virtual environment detected: {sys.prefix}")
    else:
        print("⚠️  Not in a virtual environment")
        response = input("Do you want to continue without a virtual environment? (y/N): ")
        if response.lower() != 'y':
            print("Please activate a virtual environment and run this script again")
            return False
    return True

def install_python_dependencies():
    """Install Python dependencies"""
    print("\n📦 Installing Python dependencies...")
    
    success, stdout, stderr = run_command(f"{sys.executable} -m pip install --upgrade pip")
    if not success:
        print(f"❌ Failed to upgrade pip: {stderr}")
        return False
    
    # Install requirements
    success, stdout, stderr = run_command(f"{sys.executable} -m pip install -r requirements.txt")
    if not success:
        print(f"❌ Failed to install requirements: {stderr}")
        return False
    
    print("✅ Python dependencies installed successfully")
    return True

def check_ollama_installed():
    """Check if Ollama is installed"""
    success, stdout, stderr = run_command("ollama --version", check=False)
    if success:
        version = stdout.strip()
        print(f"✅ Ollama is installed: {version}")
        return True
    else:
        print("❌ Ollama not found")
        return False

def install_ollama():
    """Install Ollama based on the operating system"""
    system = platform.system().lower()
    
    print(f"\n🔧 Installing Ollama for {system}...")
    
    if system == "darwin":  # macOS
        print("Installing Ollama for macOS...")
        success, stdout, stderr = run_command(
            "curl -fsSL https://ollama.ai/install.sh | sh", 
            check=False
        )
        if not success:
            print("❌ Automatic installation failed")
            print("Please install Ollama manually from: https://ollama.ai/")
            return False
            
    elif system == "linux":
        print("Installing Ollama for Linux...")
        success, stdout, stderr = run_command(
            "curl -fsSL https://ollama.ai/install.sh | sh",
            check=False
        )
        if not success:
            print("❌ Automatic installation failed")
            print("Please install Ollama manually from: https://ollama.ai/")
            return False
            
    elif system == "windows":
        print("❌ Windows automatic installation not supported")
        print("Please download and install Ollama from: https://ollama.ai/")
        print("Then run this script again")
        return False
        
    else:
        print(f"❌ Unsupported operating system: {system}")
        return False
    
    print("✅ Ollama installation completed")
    return True

def start_ollama():
    """Start Ollama service"""
    print("\n🚀 Starting Ollama service...")
    
    # Check if Ollama is already running
    success, stdout, stderr = run_command("ollama list", check=False)
    if success:
        print("✅ Ollama is already running")
        return True
    
    # Try to start Ollama
    print("Starting Ollama in background...")
    if platform.system().lower() == "windows":
        # Windows
        success, stdout, stderr = run_command("start ollama serve", check=False)
    else:
        # Unix-like systems
        success, stdout, stderr = run_command("ollama serve &", check=False)
    
    if success:
        print("✅ Ollama started successfully")
        import time
        time.sleep(3)  # Give it time to start
        return True
    else:
        print("⚠️  Could not start Ollama automatically")
        print("Please start Ollama manually with: ollama serve")
        return False

def pull_ollama_model(model_name="llama3.1"):
    """Pull the specified Ollama model"""
    print(f"\n📥 Pulling Ollama model: {model_name}")
    print("This may take several minutes depending on your internet connection...")
    
    success, stdout, stderr = run_command(f"ollama pull {model_name}")
    if success:
        print(f"✅ Model {model_name} pulled successfully")
        return True
    else:
        print(f"❌ Failed to pull model {model_name}: {stderr}")
        return False

def test_basic_components():
    """Test basic chatbot components without requiring Ollama"""
    try:
        # Test imports
        print("📦 Testing imports...")
        from vex_chatbot import VEXChatbot, VEXDataLoader
        try:
            from langchain_huggingface import HuggingFaceEmbeddings
        except ImportError:
            from langchain_community.embeddings import HuggingFaceEmbeddings
        print("✅ All required modules imported successfully")
        
        # Test database connection
        print("🗄️  Testing database connection...")
        if not Path("vex.db").exists():
            print("⚠️  VEX database not found - this is okay for initial setup")
            return True
        
        # Test data loader
        loader = VEXDataLoader("vex.db")
        print("✅ Database connection successful")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Try running: pip install -r requirements.txt")
        return False
    except Exception as e:
        print(f"❌ Component test failed: {e}")
        return False

def test_chatbot():
    """Test the chatbot installation with Ollama"""
    print("\n🔗 Testing Ollama connection...")
    
    try:
        # Import our chatbot
        from vex_chatbot import VEXChatbot
        
        # Check if database exists
        if not Path("vex.db").exists():
            print("⚠️  VEX database not found. Please make sure to import your VEX data first.")
            return True  # Not a failure, just missing data
        
        # Try to initialize (but don't actually load everything)
        chatbot = VEXChatbot()
        
        # Test Ollama connection
        if chatbot.check_ollama_connection():
            print("✅ Chatbot can connect to Ollama")
            return True
        else:
            print("❌ Chatbot cannot connect to Ollama")
            return False
            
    except Exception as e:
        print(f"❌ Ollama test failed: {e}")
        return False

def create_launcher_scripts():
    """Create convenient launcher scripts"""
    print("\n📝 Creating launcher scripts...")
    
    # CLI launcher
    cli_script = """#!/bin/bash
# VEX Chatbot CLI Launcher
source .venv/bin/activate 2>/dev/null || echo "Virtual environment not found, using system Python"
python vex_chatbot.py "$@"
"""
    
    with open("run_chatbot_cli.sh", "w") as f:
        f.write(cli_script)
    os.chmod("run_chatbot_cli.sh", 0o755)
    
    # Web interface launcher
    web_script = """#!/bin/bash
# VEX Chatbot Web Interface Launcher
source .venv/bin/activate 2>/dev/null || echo "Virtual environment not found, using system Python"
echo "🚀 Starting VEX Chatbot Web Interface..."
echo "📱 Open your browser to the URL shown below"
streamlit run vex_chatbot_web.py
"""
    
    with open("run_chatbot_web.sh", "w") as f:
        f.write(web_script)
    os.chmod("run_chatbot_web.sh", 0o755)
    
    # Windows batch files
    cli_bat = """@echo off
REM VEX Chatbot CLI Launcher for Windows
call .venv\\Scripts\\activate.bat 2>nul || echo Virtual environment not found, using system Python
python vex_chatbot.py %*
"""
    
    with open("run_chatbot_cli.bat", "w") as f:
        f.write(cli_bat)
    
    web_bat = """@echo off
REM VEX Chatbot Web Interface Launcher for Windows
call .venv\\Scripts\\activate.bat 2>nul || echo Virtual environment not found, using system Python
echo 🚀 Starting VEX Chatbot Web Interface...
echo 📱 Open your browser to the URL shown below
streamlit run vex_chatbot_web.py
"""
    
    with open("run_chatbot_web.bat", "w") as f:
        f.write(web_bat)
    
    print("✅ Launcher scripts created:")
    print("  - run_chatbot_cli.sh (Unix/Linux/macOS)")
    print("  - run_chatbot_web.sh (Unix/Linux/macOS)")
    print("  - run_chatbot_cli.bat (Windows)")
    print("  - run_chatbot_web.bat (Windows)")

def main():
    """Main setup function"""
    print("🛡️ VEX Chatbot Setup")
    print("=" * 50)
    
    # Check prerequisites
    if not check_python_version():
        sys.exit(1)
    
    if not check_virtual_env():
        sys.exit(1)
    
    # Install Python dependencies
    if not install_python_dependencies():
        print("❌ Failed to install Python dependencies")
        sys.exit(1)
    
    # Check/install Ollama
    if not check_ollama_installed():
        install_choice = input("\nWould you like to install Ollama automatically? (Y/n): ")
        if install_choice.lower() != 'n':
            if not install_ollama():
                print("❌ Ollama installation failed")
                sys.exit(1)
        else:
            print("Please install Ollama manually from: https://ollama.ai/")
            sys.exit(1)
    
    # Start Ollama
    if not start_ollama():
        print("⚠️  Please start Ollama manually with: ollama serve")
        input("Press Enter when Ollama is running...")
    
    # Pull model
    model_choice = input(f"\nWhich model would you like to use? (llama3.1/llama3.2/mistral): ").strip()
    if not model_choice:
        model_choice = "llama3.1"
    
    if not pull_ollama_model(model_choice):
        print("❌ Failed to pull model")
        sys.exit(1)
    
    # Test installation (basic components)
    print("\n🧪 Testing basic chatbot components...")
    if test_basic_components():
        print("✅ Basic components working")
        
        # Only test Ollama connection if we think it should be running
        if not test_chatbot():
            print("⚠️  Ollama connection test failed - this is normal if Ollama isn't running yet")
    else:
        print("❌ Basic component test failed")
        sys.exit(1)
    
    # Create launcher scripts
    create_launcher_scripts()
    
    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Make sure your VEX database exists (run import-vex.py if needed)")
    print("2. Start the web interface: ./run_chatbot_web.sh")
    print("3. Or use the CLI: ./run_chatbot_cli.sh --interactive")
    print("\n💡 Tips:")
    print("- Use the web interface for the best experience")
    print("- The first time you run it, vector embeddings will be created")
    print("- Check the Help tab in the web interface for usage examples")

if __name__ == "__main__":
    main() 