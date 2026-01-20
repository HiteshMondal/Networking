#!/usr/bin/env python3
"""
Cybersecurity Automation Toolkit - Dashboard Server
Serves the dashboard and provides API endpoints for log and output data
"""

import http.server
import socketserver
import json
import os
import re
from datetime import datetime
from urllib.parse import parse_qs, urlparse
from pathlib import Path

PORT = 8000
DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(DASHBOARD_DIR)
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')
OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'output')

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP request handler for the dashboard"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DASHBOARD_DIR, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        
        # API endpoints
        if parsed_path.path == '/api/dashboard-data':
            self.serve_dashboard_data()
        elif parsed_path.path == '/api/file':
            query = parse_qs(parsed_path.query)
            if 'path' in query:
                self.serve_file(query['path'][0])
            else:
                self.send_error(400, "Missing path parameter")
        else:
            # Serve static files
            super().do_GET()
    
    def serve_dashboard_data(self):
        """Serve dashboard data as JSON"""
        try:
            data = {
                'logs': self.get_log_files(),
                'outputs': self.get_output_files(),
                'history': self.get_execution_history(),
                'stats': self.calculate_stats()
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2).encode())
            
        except Exception as e:
            self.send_error(500, f"Error generating dashboard data: {str(e)}")
    
    def serve_file(self, file_path):
        """Serve a file for download or viewing"""
        try:
            # Security: prevent directory traversal
            file_path = file_path.replace('..', '')
            full_path = os.path.join(PROJECT_ROOT, file_path.lstrip('/'))
            
            if not os.path.exists(full_path):
                self.send_error(404, "File not found")
                return
            
            with open(full_path, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            
            # Determine content type
            if full_path.endswith('.log') or full_path.endswith('.txt'):
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
            elif full_path.endswith('.json'):
                self.send_header('Content-Type', 'application/json')
            elif full_path.endswith('.html'):
                self.send_header('Content-Type', 'text/html')
            else:
                self.send_header('Content-Type', 'application/octet-stream')
            
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(content)
            
        except Exception as e:
            self.send_error(500, f"Error serving file: {str(e)}")
    
    def get_log_files(self):
        """Get list of log files with metadata"""
        logs = []
        
        if not os.path.exists(LOGS_DIR):
            return logs
        
        for filename in os.listdir(LOGS_DIR):
            if filename.endswith('.log'):
                file_path = os.path.join(LOGS_DIR, filename)
                stat = os.stat(file_path)
                
                # Extract script name from log filename
                script_match = re.match(r'(.+?)_\d{8}_\d{6}\.log', filename)
                script_name = script_match.group(1) if script_match else filename
                
                logs.append({
                    'name': filename,
                    'script': script_name,
                    'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'size': stat.st_size,
                    'path': f'logs/{filename}'
                })
        
        # Sort by modification time (newest first)
        logs.sort(key=lambda x: x['timestamp'], reverse=True)
        return logs
    
    def get_output_files(self):
        """Get list of output files with metadata"""
        outputs = []
        
        if not os.path.exists(OUTPUT_DIR):
            return outputs
        
        # Icon mapping based on file extension
        icon_map = {
            '.txt': '📄',
            '.log': '📝',
            '.json': '🔍',
            '.html': '🌐',
            '.csv': '📊',
            '.xml': '📋',
            '.zip': '📦',
            '.tar': '📦',
            '.gz': '📦',
            '.pdf': '📕',
        }
        
        for filename in os.listdir(OUTPUT_DIR):
            file_path = os.path.join(OUTPUT_DIR, filename)
            
            # Skip directories
            if os.path.isdir(file_path):
                continue
            
            stat = os.stat(file_path)
            ext = os.path.splitext(filename)[1].lower()
            
            outputs.append({
                'name': filename,
                'icon': icon_map.get(ext, '📄'),
                'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'size': stat.st_size,
                'path': f'output/{filename}'
            })
        
        # Sort by modification time (newest first)
        outputs.sort(key=lambda x: x['timestamp'], reverse=True)
        return outputs
    
    def get_execution_history(self):
        """Parse log files to build execution history"""
        history = []
        
        if not os.path.exists(LOGS_DIR):
            return history
        
        for filename in os.listdir(LOGS_DIR):
            if not filename.endswith('.log'):
                continue
            
            file_path = os.path.join(LOGS_DIR, filename)
            
            # Extract script info from filename
            script_match = re.match(r'(.+?)_(\d{8}_\d{6})\.log', filename)
            if not script_match:
                continue
            
            script_name = script_match.group(1)
            timestamp_str = script_match.group(2)
            
            # Parse timestamp
            try:
                timestamp = datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
            except:
                timestamp = datetime.fromtimestamp(os.stat(file_path).st_mtime)
            
            # Determine category
            category = self.categorize_script(script_name)
            
            # Parse log for status and duration
            status, duration = self.parse_log_status(file_path)
            
            history.append({
                'name': script_name,
                'category': category,
                'status': status,
                'duration': duration,
                'timestamp': timestamp.isoformat()
            })
        
        # Sort by timestamp (newest first)
        history.sort(key=lambda x: x['timestamp'], reverse=True)
        return history
    
    def categorize_script(self, script_name):
        """Categorize script by name"""
        if 'net' in script_name.lower() or 'network' in script_name.lower():
            return 'network'
        elif 'secure' in script_name.lower() or 'security' in script_name.lower():
            return 'security'
        elif 'forensic' in script_name.lower():
            return 'forensic'
        elif 'recon' in script_name.lower() or 'web' in script_name.lower():
            return 'recon'
        else:
            return 'other'
    
    def parse_log_status(self, log_path):
        """Parse log file to determine status and duration"""
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Determine status
            status = 'success'
            if 'error' in content.lower() or 'failed' in content.lower():
                status = 'error'
            elif 'warning' in content.lower():
                status = 'warning'
            
            # Try to extract duration from log
            start_match = re.search(r'started at (.+?) ===', content)
            end_match = re.search(r'completed at (.+?) with', content)
            
            duration = 'N/A'
            if start_match and end_match:
                try:
                    start = datetime.strptime(start_match.group(1).strip(), '%a %b %d %H:%M:%S %Z %Y')
                    end = datetime.strptime(end_match.group(1).strip(), '%a %b %d %H:%M:%S %Z %Y')
                    diff = int((end - start).total_seconds())
                    duration = f"{diff // 60}m {diff % 60}s"
                except:
                    pass
            
            # Check exit code
            exit_match = re.search(r'exit code (\d+)', content)
            if exit_match and exit_match.group(1) != '0':
                status = 'error'
            
            return status, duration
            
        except Exception as e:
            return 'unknown', 'N/A'
    
    def calculate_stats(self):
        """Calculate dashboard statistics"""
        history = self.get_execution_history()
        
        stats = {
            'total': len(history),
            'successful': sum(1 for h in history if h['status'] == 'success'),
            'warnings': sum(1 for h in history if h['status'] == 'warning'),
            'failed': sum(1 for h in history if h['status'] == 'error')
        }
        
        return stats
    
    def log_message(self, format, *args):
        """Custom log message format"""
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {format % args}")


def main():
    """Start the dashboard server"""
    
    # Ensure directories exist
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Start server
    with socketserver.TCPServer(("", PORT), DashboardHandler) as httpd:
        print("=" * 60)
        print("  Cybersecurity Automation Toolkit - Dashboard Server")
        print("=" * 60)
        print(f"\n✓ Server started successfully")
        print(f"✓ Dashboard URL: http://localhost:{PORT}")
        print(f"✓ Logs directory: {LOGS_DIR}")
        print(f"✓ Output directory: {OUTPUT_DIR}")
        print(f"\nPress Ctrl+C to stop the server\n")
        print("=" * 60)
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n\n" + "=" * 60)
            print("  Server stopped")
            print("=" * 60)


if __name__ == '__main__':
    main()