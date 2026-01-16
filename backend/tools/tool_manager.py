import subprocess
import json
import os
import sys
from pathlib import Path
import shutil
import requests
from datetime import datetime
from database.models import db, Tool
from config import config

class ToolManager:
    def __init__(self):
        self.tools_config = self.load_tools_config()
        self.installation_log = []
        
    def load_tools_config(self):
        """Load tools configuration from JSON file"""
        config_path = Path(__file__).parent / 'tool_inventory.json'
        with open(config_path, 'r') as f:
            return json.load(f)
    
    def check_tool_installed(self, tool_name):
        """Check if a tool is installed"""
        tool_config = self.tools_config.get(tool_name, {})
        
        if tool_config.get('check_command'):
            try:
                result = subprocess.run(
                    tool_config['check_command'],
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.returncode == 0
            except:
                return False
        
        # Fallback: check in PATH
        return shutil.which(tool_name) is not None
    
    def install_tool(self, tool_name):
        """Install a specific tool"""
        tool_config = self.tools_config.get(tool_name, {})
        
        if not tool_config:
            self.installation_log.append(f"Error: No configuration found for {tool_name}")
            return False
        
        install_commands = tool_config.get('install_commands', [])
        
        for cmd in install_commands:
            try:
                self.installation_log.append(f"Executing: {cmd}")
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minutes timeout
                )
                
                if result.returncode != 0:
                    self.installation_log.append(f"Error: {result.stderr}")
                    return False
                    
            except subprocess.TimeoutExpired:
                self.installation_log.append(f"Timeout installing {tool_name}")
                return False
            except Exception as e:
                self.installation_log.append(f"Exception: {str(e)}")
                return False
        
        # Update database
        try:
            tool = Tool.query.filter_by(name=tool_name).first()
            if tool:
                tool.is_installed = True
                tool.last_checked = datetime.utcnow()
                db.session.commit()
        except Exception as e:
            self.installation_log.append(f"DB Error: {str(e)}")
        
        return True
    
    def check_all_tools(self):
        """Check status of all tools"""
        tools_status = {}
        
        for tool_name in self.tools_config.keys():
            is_installed = self.check_tool_installed(tool_name)
            tools_status[tool_name] = {
                'installed': is_installed,
                'config': self.tools_config[tool_name]
            }
            
            # Update database
            try:
                tool = Tool.query.filter_by(name=tool_name).first()
                if tool:
                    tool.is_installed = is_installed
                    tool.last_checked = datetime.utcnow()
            except Exception as e:
                print(f"Error updating tool {tool_name}: {e}")
        
        db.session.commit()
        return tools_status
    
    def install_missing_tools(self):
        """Install all missing tools"""
        status = self.check_all_tools()
        missing_tools = [tool for tool, info in status.items() if not info['installed']]
        
        results = {}
        for tool in missing_tools:
            self.installation_log = []
            success = self.install_tool(tool)
            results[tool] = {
                'success': success,
                'log': self.installation_log.copy()
            }
        
        return results
    
    def get_tool_info(self, tool_name):
        """Get information about a specific tool"""
        tool_config = self.tools_config.get(tool_name, {})
        is_installed = self.check_tool_installed(tool_name)
        
        return {
            'name': tool_name,
            'installed': is_installed,
            'category': tool_config.get('category'),
            'description': tool_config.get('description'),
            'usage': tool_config.get('usage'),
            'dependencies': tool_config.get('dependencies', [])
        }
    
    def run_tool(self, tool_name, args, timeout=300):
        """Run a tool with arguments"""
        if not self.check_tool_installed(tool_name):
            return {
                'success': False,
                'error': f"Tool {tool_name} is not installed",
                'output': '',
                'returncode': -1
            }
        
        tool_config = self.tools_config.get(tool_name, {})
        command = tool_config.get('base_command', tool_name)
        
        full_command = f"{command} {args}"
        
        try:
            result = subprocess.run(
                full_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'returncode': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f"Tool timeout after {timeout} seconds",
                'output': '',
                'returncode': -1
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'output': '',
                'returncode': -1
            }

# Singleton instance
tool_manager = ToolManager()
