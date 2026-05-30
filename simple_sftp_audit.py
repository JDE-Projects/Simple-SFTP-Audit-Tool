#!/usr/bin/env python3
"""
Simple SFTP Audit Tool - A standalone graphical interface for ssh-audit
by JDE-Projects

Redesigned for clear, at-a-glance results with:
- Overall security grade (A-F)
- Server information (software, OS, compression)
- Security advisories
- Organized sections by algorithm type with key sizes
- Simple red/yellow/green color coding

Build instructions:
  1. pip install ssh-audit pyinstaller
  2. pyinstaller --onefile --windowed --name "SimpleSFTPAuditTool" simple_sftp_audit.py
"""

import io
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, font as tkfont
from contextlib import redirect_stdout, redirect_stderr
import re


class SSHAuditGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple SFTP Audit Tool")
        self.root.geometry("1000x800")
        self.root.minsize(800, 600)
        self.root.configure(bg="#1e1e1e")
        
        # Set window icon
        self._set_icon()
        
        self.audit_running = False
        self.audit_thread = None
        
        self.create_widgets()
    
    def _set_icon(self):
        """Set the window icon, handling both development and PyInstaller bundled modes."""
        import os
        try:
            # When running as PyInstaller bundle, files are in sys._MEIPASS
            if getattr(sys, 'frozen', False):
                icon_path = os.path.join(sys._MEIPASS, 'simple_sftp_audit.ico')
            else:
                # Development mode - look in same directory as script
                icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'simple_sftp_audit.ico')
            
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass  # Silently ignore if icon can't be loaded
        
    def create_widgets(self):
        # Main container with dark theme
        main_frame = tk.Frame(self.root, bg="#1e1e1e", padx=15, pady=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title bar
        title_frame = tk.Frame(main_frame, bg="#1e1e1e")
        title_frame.pack(fill=tk.X, pady=(0, 15))
        
        title_label = tk.Label(title_frame, text="Simple SFTP Audit Tool", 
                               font=("Segoe UI", 18, "bold"), fg="#ffffff", bg="#1e1e1e")
        title_label.pack(side=tk.LEFT)
        
        # Version info and link
        try:
            from ssh_audit.ssh_audit import VERSION
            import webbrowser
            
            ver_frame = tk.Frame(title_frame, bg="#1e1e1e")
            ver_frame.pack(side=tk.RIGHT)
            
            author_label = tk.Label(ver_frame, text="by JDE-Projects", 
                                font=("Segoe UI", 9, "bold"), fg="#888888", bg="#1e1e1e")
            author_label.pack(anchor="e")
            
            ver_label = tk.Label(ver_frame, text=f"Powered by ssh-audit {VERSION}", 
                                font=("Segoe UI", 10), fg="#666666", bg="#1e1e1e")
            ver_label.pack(anchor="e")
            
            link_label = tk.Label(ver_frame, text="github.com/jtesta/ssh-audit", 
                                 font=("Segoe UI", 9, "underline"), fg="#4a9eff", bg="#1e1e1e",
                                 cursor="hand2")
            link_label.pack(anchor="e")
            link_label.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/jtesta/ssh-audit"))
        except:
            pass
        
        # Input frame
        input_frame = tk.Frame(main_frame, bg="#2d2d2d", padx=15, pady=15)
        input_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Host input row
        input_row = tk.Frame(input_frame, bg="#2d2d2d")
        input_row.pack(fill=tk.X)
        
        tk.Label(input_row, text="Host/IP:", font=("Segoe UI", 11), 
                fg="#ffffff", bg="#2d2d2d").pack(side=tk.LEFT)
        
        self.host_entry = tk.Entry(input_row, width=35, font=("Segoe UI", 12),
                                   bg="#3d3d3d", fg="#ffffff", insertbackground="#ffffff",
                                   relief=tk.FLAT, highlightthickness=1, highlightcolor="#4a9eff")
        self.host_entry.pack(side=tk.LEFT, padx=(10, 25), ipady=5)
        self.host_entry.bind("<Return>", lambda e: self.run_audit())
        self.host_entry.focus()
        
        tk.Label(input_row, text="Port:", font=("Segoe UI", 11),
                fg="#ffffff", bg="#2d2d2d").pack(side=tk.LEFT)
        
        self.port_entry = tk.Entry(input_row, width=6, font=("Segoe UI", 12),
                                   bg="#3d3d3d", fg="#ffffff", insertbackground="#ffffff",
                                   relief=tk.FLAT, highlightthickness=1, highlightcolor="#4a9eff")
        self.port_entry.pack(side=tk.LEFT, padx=(10, 25), ipady=5)
        
        # Buttons
        self.audit_btn = tk.Button(input_row, text="▶  Run Audit", font=("Segoe UI", 11, "bold"),
                                   bg="#4a9eff", fg="#ffffff", relief=tk.FLAT, padx=20, pady=5,
                                   cursor="hand2", command=self.run_audit)
        self.audit_btn.pack(side=tk.LEFT, padx=(10, 10))
        
        self.clear_btn = tk.Button(input_row, text="Clear", font=("Segoe UI", 10),
                                   bg="#555555", fg="#ffffff", relief=tk.FLAT, padx=15, pady=5,
                                   cursor="hand2", command=self.clear_results)
        self.clear_btn.pack(side=tk.LEFT)
        
        # Results area (scrollable)
        self.results_canvas = tk.Canvas(main_frame, bg="#1e1e1e", highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.results_canvas.yview)
        self.results_frame = tk.Frame(self.results_canvas, bg="#1e1e1e")
        
        self.results_frame.bind("<Configure>", 
            lambda e: self.results_canvas.configure(scrollregion=self.results_canvas.bbox("all")))
        
        self.canvas_window = self.results_canvas.create_window((0, 0), window=self.results_frame, anchor="nw")
        self.results_canvas.configure(yscrollcommand=scrollbar.set)
        
        # Make canvas resize with window
        self.results_canvas.bind("<Configure>", self._on_canvas_configure)
        
        # Mouse wheel scrolling
        self.results_canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        self.results_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Show initial message
        self.show_welcome_message()
        
    def _on_canvas_configure(self, event):
        self.results_canvas.itemconfig(self.canvas_window, width=event.width)
        
    def _on_mousewheel(self, event):
        self.results_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
    def show_welcome_message(self):
        welcome = tk.Frame(self.results_frame, bg="#1e1e1e", pady=50)
        welcome.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(welcome, text="Enter a hostname or IP address above to audit an SFTP server",
                font=("Segoe UI", 12), fg="#666666", bg="#1e1e1e").pack()
        
        tk.Label(welcome, text="\nResults will show:", font=("Segoe UI", 11), 
                fg="#555555", bg="#1e1e1e").pack(pady=(20,5))
        
        legend_frame = tk.Frame(welcome, bg="#1e1e1e")
        legend_frame.pack()
        
        # Secure
        secure_frame = tk.Frame(legend_frame, bg="#1e1e1e")
        secure_frame.pack(side=tk.LEFT, padx=15)
        tk.Label(secure_frame, text="●", font=("Segoe UI", 11), fg="#4ade80", bg="#1e1e1e").pack(side=tk.LEFT)
        tk.Label(secure_frame, text=" Secure", font=("Segoe UI", 11), fg="#4ade80", bg="#1e1e1e").pack(side=tk.LEFT)
        
        # Warnings
        warn_frame = tk.Frame(legend_frame, bg="#1e1e1e")
        warn_frame.pack(side=tk.LEFT, padx=15)
        tk.Label(warn_frame, text="●", font=("Segoe UI", 11), fg="#fbbf24", bg="#1e1e1e").pack(side=tk.LEFT)
        tk.Label(warn_frame, text=" Warnings", font=("Segoe UI", 11), fg="#fbbf24", bg="#1e1e1e").pack(side=tk.LEFT)
        
        # Failures
        fail_frame = tk.Frame(legend_frame, bg="#1e1e1e")
        fail_frame.pack(side=tk.LEFT, padx=15)
        tk.Label(fail_frame, text="●", font=("Segoe UI", 11), fg="#f87171", bg="#1e1e1e").pack(side=tk.LEFT)
        tk.Label(fail_frame, text=" Failures", font=("Segoe UI", 11), fg="#f87171", bg="#1e1e1e").pack(side=tk.LEFT)

    def clear_results(self):
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        self.show_welcome_message()
        
    def run_audit(self):
        if self.audit_running:
            return
            
        host = self.host_entry.get().strip()
        if not host:
            messagebox.showwarning("Input Required", "Please enter a hostname or IP address.")
            self.host_entry.focus()
            return
        
        # Parse host:port if present
        if ':' in host:
            match = re.match(r'^(.+):(\d+)$', host)
            if match:
                host = match.group(1)
                port = match.group(2)
                # Update the fields visually
                self.host_entry.delete(0, tk.END)
                self.host_entry.insert(0, host)
                self.port_entry.delete(0, tk.END)
                self.port_entry.insert(0, port)
        
        port = self.port_entry.get().strip()
        
        # Check if port is empty
        if not port:
            self._show_port_error()
            self.port_entry.focus()
            return
        
        try:
            port_num = int(port)
        except ValueError:
            messagebox.showerror("Invalid Port", "Port must be a number.")
            return
        
        # Clear previous results
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        # Update UI
        self.audit_running = True
        self.audit_btn.config(state=tk.DISABLED, bg="#666666")
        
        # Show loading
        loading = tk.Label(self.results_frame, text="🔄 Scanning...", 
                          font=("Segoe UI", 14), fg="#4a9eff", bg="#1e1e1e", pady=50)
        loading.pack()
        
        # Run audit in thread
        self.audit_thread = threading.Thread(
            target=self._execute_audit, 
            args=(host, port_num), 
            daemon=True
        )
        self.audit_thread.start()
        
    def _execute_audit(self, host, port):
        """Execute ssh-audit and parse results."""
        try:
            from ssh_audit.ssh_audit import main
            
            # Build arguments - use verbose mode to get more info
            args = ['ssh-audit', '-v', '-4', '-t', '10', '-p', str(port), host]
            
            original_argv = sys.argv
            sys.argv = args
            
            try:
                output_buffer = io.StringIO()
                
                with redirect_stdout(output_buffer), redirect_stderr(output_buffer):
                    try:
                        exit_code = main()
                    except SystemExit as e:
                        exit_code = e.code if e.code is not None else 0
                
                output = output_buffer.getvalue()
                
                # Check if we got meaningful output
                if not output.strip() or ('kex' not in output.lower() and 'key' not in output.lower()):
                    self.root.after(0, self._show_connection_error, host, port)
                else:
                    self.root.after(0, self._parse_and_display_results, output, host, port)
                
            finally:
                sys.argv = original_argv
                
        except ImportError as e:
            self.root.after(0, self._show_error, f"ssh-audit library not found: {e}")
        except Exception as e:
            self.root.after(0, self._show_connection_error, host, port)
        finally:
            self.root.after(0, self._audit_complete)
            
    def _parse_and_display_results(self, output, host, port):
        """Parse ssh-audit output and display in organized format."""
        
        # Clear loading message
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        # Parse the output
        lines = output.split('\n')
        
        fail_count = 0
        warn_count = 0
        good_count = 0
        
        current_section = None
        
        parsed = {
            'software': '',
            'os': '',
            'compression': [],
            'security_issues': [],
            'kex': [],
            'key': [],
            'enc': [],
            'mac': [],
            'fingerprints': [],
            'recommendations': [],
        }
        
        for line in lines:
            # Strip ANSI codes
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()
            
            if not clean:
                continue
            
            # Detect section headers
            if clean.startswith('# general'):
                current_section = 'general'
                continue
            elif clean.startswith('# key exchange algorithms'):
                current_section = 'kex'
                continue
            elif clean.startswith('# host-key algorithms'):
                current_section = 'key'
                continue
            elif clean.startswith('# encryption algorithms'):
                current_section = 'enc'
                continue
            elif clean.startswith('# message authentication'):
                current_section = 'mac'
                continue
            elif clean.startswith('# fingerprints'):
                current_section = 'fingerprints'
                continue
            elif clean.startswith('# algorithm recommendations'):
                current_section = 'recommendations'
                continue
            elif clean.startswith('# additional info'):
                current_section = 'additional'
                continue
            elif clean.startswith('# compression algorithms'):
                current_section = 'compression'
                continue
            elif clean.startswith('#'):
                current_section = None
                continue
            
            # Parse general info
            if current_section == 'general':
                if '(gen)' in clean:
                    gen_content = clean.replace('(gen)', '').strip()
                    gen_lower = gen_content.lower()
                    
                    # Software/banner info - try multiple patterns
                    if 'software:' in gen_lower:
                        parsed['software'] = gen_content.split(':', 1)[1].strip() if ':' in gen_content else gen_content
                    elif 'os:' in gen_lower:
                        parsed['os'] = gen_content.split(':', 1)[1].strip() if ':' in gen_content else gen_content
                    elif 'banner:' in gen_lower:
                        # Capture raw banner if present
                        banner = gen_content.split(':', 1)[1].strip() if ':' in gen_content else gen_content
                        if not parsed['software']:
                            parsed['software'] = banner
                    elif gen_content.startswith('SSH-') or 'ssh' in gen_lower:
                        # Capture SSH version string as software if nothing else
                        if not parsed['software']:
                            parsed['software'] = gen_content
                    
                    # Check for security issues in general section
                    if '[fail]' in clean.lower() or '[warn]' in clean.lower():
                        parsed['security_issues'].append(gen_content)
            
            # Parse compression
            elif current_section == 'compression':
                if '(cmp)' in clean:
                    cmp_name = re.search(r'\(cmp\)\s+(\S+)', clean)
                    if cmp_name:
                        parsed['compression'].append(cmp_name.group(1))
            
            # Parse algorithm lines
            elif current_section in ['kex', 'key', 'enc', 'mac']:
                # Extract algorithm name and details
                match = re.match(r'\((?:kex|key|enc|mac)\)\s+(\S+)', clean)
                if match:
                    alg_name = match.group(1)
                    
                    # Extract key size if present (e.g., "(4096-bit)")
                    size_match = re.search(r'\((\d+)-bit\)', clean)
                    key_size = size_match.group(1) if size_match else None
                    
                    # Determine status for this line
                    line_status = 'good'
                    if '[fail]' in clean.lower():
                        line_status = 'fail'
                    elif '[warn]' in clean.lower():
                        line_status = 'warn'
                    
                    # Extract reason if present (only for fail/warn, skip info-only lines)
                    reason = ''
                    reason_match = re.search(r'--\s+\[(fail|warn|info)\]\s+(.+)$', clean)
                    if reason_match:
                        reason_type = reason_match.group(1)
                        reason_text = reason_match.group(2)
                        # Only keep fail/warn reasons, skip pure info like "available since..."
                        if reason_type in ['fail', 'warn']:
                            reason = reason_text
                    
                    # Check if this algorithm already exists in the list
                    existing = None
                    for alg in parsed[current_section]:
                        if alg['name'] == alg_name:
                            existing = alg
                            break
                    
                    if existing:
                        # Update existing entry - use worst status (fail > warn > good)
                        status_priority = {'fail': 3, 'warn': 2, 'good': 1}
                        if status_priority[line_status] > status_priority[existing['status']]:
                            existing['status'] = line_status
                        # Append reason if it's new and meaningful
                        if reason and reason not in existing['reason']:
                            if existing['reason']:
                                existing['reason'] += '; ' + reason
                            else:
                                existing['reason'] = reason
                        # Update key size if we found one
                        if key_size and not existing.get('key_size'):
                            existing['key_size'] = key_size
                    else:
                        # New algorithm - add to list
                        parsed[current_section].append({
                            'name': alg_name,
                            'status': line_status,
                            'reason': reason,
                            'key_size': key_size
                        })
                    
            elif current_section == 'fingerprints':
                if '(fin)' in clean:
                    parsed['fingerprints'].append(clean.replace('(fin)', '').strip())
                    
            elif current_section == 'recommendations':
                if '(rec)' in clean:
                    parsed['recommendations'].append(clean.replace('(rec)', '').strip())
                    
            elif current_section == 'additional':
                # Security warnings often appear here
                if '(nfo)' in clean or '(inf)' in clean:
                    info_text = re.sub(r'\(nfo\)|\(inf\)', '', clean).strip()
                    if info_text:
                        parsed['security_issues'].append(info_text)
        
        # Count consolidated algorithms by status
        fail_count = 0
        warn_count = 0
        good_count = 0
        for section in ['kex', 'key', 'enc', 'mac']:
            for alg in parsed[section]:
                if alg['status'] == 'fail':
                    fail_count += 1
                elif alg['status'] == 'warn':
                    warn_count += 1
                else:
                    good_count += 1
        
        # Now display the results
        self._display_parsed_results(parsed, host, port, fail_count, warn_count, good_count)
        
    def _display_parsed_results(self, parsed, host, port, fails, warns, goods):
        """Display the parsed results in a clean visual format."""
        
        container = self.results_frame
        
        # Header with host info
        header = tk.Frame(container, bg="#2d2d2d", padx=20, pady=15)
        header.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(header, text=f"Audit complete for {host}:{port}", 
                font=("Segoe UI", 14, "bold"), fg="#ffffff", bg="#2d2d2d").pack(anchor="w")
        
        # Overall Grade
        grade, grade_color = self._calculate_grade(fails, warns, goods)
        
        grade_frame = tk.Frame(container, bg="#1e1e1e")
        grade_frame.pack(fill=tk.X, pady=(0, 20))
        
        grade_box = tk.Frame(grade_frame, bg=grade_color, padx=30, pady=15)
        grade_box.pack()
        
        tk.Label(grade_box, text=f"Grade: {grade}", font=("Segoe UI", 28, "bold"),
                fg="#ffffff", bg=grade_color).pack()
        
        # Summary stats
        stats_frame = tk.Frame(grade_frame, bg="#1e1e1e")
        stats_frame.pack(pady=(10, 0))
        
        # Failures
        fail_frame = tk.Frame(stats_frame, bg="#1e1e1e")
        fail_frame.pack(side=tk.LEFT, padx=15)
        tk.Label(fail_frame, text="●", font=("Segoe UI", 11), fg="#f87171", bg="#1e1e1e").pack(side=tk.LEFT)
        tk.Label(fail_frame, text=f" {fails} Failures", font=("Segoe UI", 11), fg="#f87171", bg="#1e1e1e").pack(side=tk.LEFT)
        
        # Warnings
        warn_frame = tk.Frame(stats_frame, bg="#1e1e1e")
        warn_frame.pack(side=tk.LEFT, padx=15)
        tk.Label(warn_frame, text="●", font=("Segoe UI", 11), fg="#fbbf24", bg="#1e1e1e").pack(side=tk.LEFT)
        tk.Label(warn_frame, text=f" {warns} Warnings", font=("Segoe UI", 11), fg="#fbbf24", bg="#1e1e1e").pack(side=tk.LEFT)
        
        # Secure
        good_frame = tk.Frame(stats_frame, bg="#1e1e1e")
        good_frame.pack(side=tk.LEFT, padx=15)
        tk.Label(good_frame, text="●", font=("Segoe UI", 11), fg="#4ade80", bg="#1e1e1e").pack(side=tk.LEFT)
        tk.Label(good_frame, text=f" {goods} Secure", font=("Segoe UI", 11), fg="#4ade80", bg="#1e1e1e").pack(side=tk.LEFT)
        
        # Server Information section (moved above Security Checklist)
        if parsed['software'] or parsed['os'] or parsed['compression']:
            info_frame = tk.Frame(container, bg="#2d2d2d", padx=15, pady=15)
            info_frame.pack(fill=tk.X, pady=(15, 10), padx=10)
            
            tk.Label(info_frame, text="📋 Server Information", font=("Segoe UI", 12, "bold"),
                    fg="#ffffff", bg="#2d2d2d").pack(anchor="w", pady=(0, 10))
            
            info_grid = tk.Frame(info_frame, bg="#2d2d2d")
            info_grid.pack(fill=tk.X, anchor="w")
            
            if parsed['software']:
                row = tk.Frame(info_grid, bg="#2d2d2d")
                row.pack(fill=tk.X, pady=2, anchor="w")
                tk.Label(row, text="Software:", font=("Segoe UI", 10, "bold"),
                        fg="#888888", bg="#2d2d2d", width=12, anchor="w").pack(side=tk.LEFT)
                tk.Label(row, text=parsed['software'], font=("Consolas", 10),
                        fg="#4ade80", bg="#2d2d2d").pack(side=tk.LEFT)
            
            if parsed['os']:
                row = tk.Frame(info_grid, bg="#2d2d2d")
                row.pack(fill=tk.X, pady=2, anchor="w")
                tk.Label(row, text="OS:", font=("Segoe UI", 10, "bold"),
                        fg="#888888", bg="#2d2d2d", width=12, anchor="w").pack(side=tk.LEFT)
                tk.Label(row, text=parsed['os'], font=("Consolas", 10),
                        fg="#ffffff", bg="#2d2d2d").pack(side=tk.LEFT)
            
            if parsed['compression']:
                row = tk.Frame(info_grid, bg="#2d2d2d")
                row.pack(fill=tk.X, pady=2, anchor="w")
                tk.Label(row, text="Compression:", font=("Segoe UI", 10, "bold"),
                        fg="#888888", bg="#2d2d2d", width=12, anchor="w").pack(side=tk.LEFT)
                tk.Label(row, text=", ".join(parsed['compression']), font=("Consolas", 10),
                        fg="#ffffff", bg="#2d2d2d").pack(side=tk.LEFT)
        
        # Security Checklist Summary
        checklist = self._generate_security_checklist(parsed)
        if checklist:
            checklist_frame = tk.Frame(container, bg="#1f3d1f", padx=15, pady=15)
            checklist_frame.pack(fill=tk.X, pady=(0, 10), padx=10)
            
            tk.Label(checklist_frame, text="🛡️ Security Checklist", font=("Segoe UI", 12, "bold"),
                    fg="#4ade80", bg="#1f3d1f").pack(anchor="w", pady=(0, 10))
            
            for item in checklist:
                item_frame = tk.Frame(checklist_frame, bg="#1f3d1f")
                item_frame.pack(fill=tk.X, pady=1, anchor="w")
                
                if item['status'] == 'good':
                    icon = "✓"
                    color = "#4ade80"
                elif item['status'] == 'bad':
                    icon = "✗"
                    color = "#f87171"
                else:  # warn
                    icon = "⚠"
                    color = "#fbbf24"
                
                tk.Label(item_frame, text=icon, font=("Segoe UI", 10),
                        fg=color, bg="#1f3d1f", width=2).pack(side=tk.LEFT)
                tk.Label(item_frame, text=item['text'], font=("Segoe UI", 10),
                        fg=color, bg="#1f3d1f").pack(side=tk.LEFT)
        
        # Security Issues / Advisories
        if parsed['security_issues']:
            issues_frame = tk.Frame(container, bg="#3d1f1f", padx=15, pady=15)
            issues_frame.pack(fill=tk.X, pady=(0, 10), padx=10)
            
            tk.Label(issues_frame, text="⚠️ Security Advisories", font=("Segoe UI", 12, "bold"),
                    fg="#f87171", bg="#3d1f1f").pack(anchor="w", pady=(0, 10))
            
            for issue in parsed['security_issues']:
                # Wrap long text
                issue_label = tk.Label(issues_frame, text=f"• {issue}", font=("Segoe UI", 10),
                        fg="#fbbf24", bg="#3d1f1f", wraplength=850, justify="left", anchor="w")
                issue_label.pack(fill=tk.X, pady=2, anchor="w")
        
        # Algorithm sections
        sections = [
            ('Key Exchange Algorithms', 'kex'),
            ('Host Key Algorithms', 'key'),
            ('Encryption Ciphers', 'enc'),
            ('Message Authentication Codes (MAC)', 'mac'),
        ]
        
        for title, key in sections:
            if parsed[key]:
                self._create_section(container, title, parsed[key])
        
        # Recommendations section
        if parsed['recommendations']:
            rec_frame = tk.Frame(container, bg="#1f2d3d", padx=15, pady=15)
            rec_frame.pack(fill=tk.X, pady=(0, 10), padx=10)
            
            tk.Label(rec_frame, text="💡 Recommendations", font=("Segoe UI", 12, "bold"),
                    fg="#4a9eff", bg="#1f2d3d").pack(anchor="w", pady=(0, 10))
            
            for rec in parsed['recommendations']:
                rec_label = tk.Label(rec_frame, text=f"• {rec}", font=("Segoe UI", 10),
                        fg="#88ccff", bg="#1f2d3d", wraplength=850, justify="left", anchor="w")
                rec_label.pack(fill=tk.X, pady=2, anchor="w")
        
        # Fingerprints section
        if parsed['fingerprints']:
            fp_frame = tk.Frame(container, bg="#2d2d2d", padx=15, pady=15)
            fp_frame.pack(fill=tk.X, pady=(0, 10), padx=10)
            
            tk.Label(fp_frame, text="🔑 Host Key Fingerprints", font=("Segoe UI", 12, "bold"),
                    fg="#ffffff", bg="#2d2d2d").pack(anchor="w")
            
            for fp in parsed['fingerprints']:
                tk.Label(fp_frame, text=fp, font=("Consolas", 9),
                        fg="#888888", bg="#2d2d2d", wraplength=850, justify="left").pack(anchor="w", pady=2)
        
        # Copy button
        copy_frame = tk.Frame(container, bg="#1e1e1e", pady=15)
        copy_frame.pack(fill=tk.X)
        
        copy_btn = tk.Button(copy_frame, text="📋  Copy Report to Clipboard", 
                            font=("Segoe UI", 10), bg="#555555", fg="#ffffff",
                            relief=tk.FLAT, padx=15, pady=8, cursor="hand2",
                            command=lambda: self._copy_report(parsed, host, port, fails, warns, goods))
        copy_btn.pack()
        
    def _create_section(self, parent, title, algorithms):
        """Create a section for algorithm display."""
        
        section = tk.Frame(parent, bg="#2d2d2d", padx=15, pady=15)
        section.pack(fill=tk.X, pady=(0, 10), padx=10)
        
        # Section header
        tk.Label(section, text=title, font=("Segoe UI", 12, "bold"),
                fg="#ffffff", bg="#2d2d2d").pack(anchor="w", pady=(0, 10))
        
        # Algorithm list
        for alg in algorithms:
            self._create_algorithm_row(section, alg)
            
    def _create_algorithm_row(self, parent, alg):
        """Create a row for a single algorithm."""
        
        row = tk.Frame(parent, bg="#2d2d2d")
        row.pack(fill=tk.X, pady=2)
        
        # Status indicator - use colored bullet instead of emoji
        if alg['status'] == 'fail':
            indicator_color = "#f87171"
            name_color = "#f87171"
        elif alg['status'] == 'warn':
            indicator_color = "#fbbf24"
            name_color = "#fbbf24"
        else:
            indicator_color = "#4ade80"
            name_color = "#4ade80"
        
        tk.Label(row, text="●", font=("Segoe UI", 10),
                fg=indicator_color, bg="#2d2d2d").pack(side=tk.LEFT, padx=(0, 8))
        
        # Algorithm name
        alg_text = alg['name']
        if alg.get('key_size'):
            alg_text += f"  ({alg['key_size']}-bit)"
        
        tk.Label(row, text=alg_text, font=("Consolas", 10),
                fg=name_color, bg="#2d2d2d").pack(side=tk.LEFT)
        
        if alg['reason']:
            tk.Label(row, text=f"  —  {alg['reason']}", font=("Segoe UI", 9),
                    fg="#888888", bg="#2d2d2d").pack(side=tk.LEFT)
    
    def _generate_security_checklist(self, parsed):
        """Generate a security checklist based on what's supported/not supported."""
        checklist = []
        
        # Get all algorithm names (lowercase for easier matching)
        all_kex = [a['name'].lower() for a in parsed.get('kex', [])]
        all_key = [a['name'].lower() for a in parsed.get('key', [])]
        all_enc = [a['name'].lower() for a in parsed.get('enc', [])]
        all_mac = [a['name'].lower() for a in parsed.get('mac', [])]
        
        # Check for SHA-1 based algorithms
        sha1_host_keys = ['ssh-rsa', 'ssh-dss', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']
        has_sha1_keys = any(k in all_key for k in sha1_host_keys if 'sha2' not in k and k == 'ssh-rsa' or k == 'ssh-dss')
        
        if 'ssh-rsa' in all_key:
            checklist.append({'status': 'bad', 'text': 'Supports ssh-rsa (SHA-1 signatures) - deprecated'})
        else:
            checklist.append({'status': 'good', 'text': 'No SHA-1 signature algorithms (ssh-rsa not supported)'})
        
        # Check for modern key exchange
        modern_kex = ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'sntrup761x25519-sha512@openssh.com']
        has_modern_kex = any(k in all_kex for k in modern_kex)
        if has_modern_kex:
            checklist.append({'status': 'good', 'text': 'Supports modern key exchange (Curve25519)'})
        else:
            checklist.append({'status': 'warn', 'text': 'No Curve25519 key exchange support'})
        
        # Check for weak key exchanges
        weak_kex = ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1']
        has_weak_kex = any(k in all_kex for k in weak_kex)
        if has_weak_kex:
            checklist.append({'status': 'bad', 'text': 'Supports weak key exchange algorithms (SHA-1 based DH)'})
        else:
            checklist.append({'status': 'good', 'text': 'No weak key exchange algorithms'})
        
        # Check for CBC mode ciphers
        cbc_ciphers = [c for c in all_enc if '-cbc' in c]
        if cbc_ciphers:
            checklist.append({'status': 'warn', 'text': f'Supports CBC mode ciphers ({len(cbc_ciphers)} found) - vulnerable to padding oracle attacks'})
        else:
            checklist.append({'status': 'good', 'text': 'No CBC mode ciphers'})
        
        # Check for modern ciphers (AEAD)
        aead_ciphers = ['chacha20-poly1305@openssh.com', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com']
        has_aead = any(c in all_enc for c in aead_ciphers)
        if has_aead:
            checklist.append({'status': 'good', 'text': 'Supports authenticated encryption (AEAD ciphers)'})
        else:
            checklist.append({'status': 'warn', 'text': 'No AEAD ciphers (ChaCha20-Poly1305 or AES-GCM)'})
        
        # Check for arcfour/RC4
        if any('arcfour' in c for c in all_enc):
            checklist.append({'status': 'bad', 'text': 'Supports arcfour/RC4 - broken cipher'})
        
        # Check for 3DES
        if any('3des' in c for c in all_enc):
            checklist.append({'status': 'bad', 'text': 'Supports 3DES - weak cipher'})
        
        # Check for MD5 MACs
        if any('md5' in m for m in all_mac):
            checklist.append({'status': 'bad', 'text': 'Supports MD5-based MACs - weak hash'})
        
        # Check for ETM (Encrypt-then-MAC) support
        etm_macs = [m for m in all_mac if '-etm@' in m]
        if etm_macs:
            checklist.append({'status': 'good', 'text': 'Supports Encrypt-then-MAC (ETM) modes'})
        else:
            checklist.append({'status': 'warn', 'text': 'No Encrypt-then-MAC (ETM) support'})
        
        # Check for Ed25519 host key
        if any('ed25519' in k for k in all_key):
            checklist.append({'status': 'good', 'text': 'Supports Ed25519 host keys'})
        
        return checklist
            
    def _calculate_grade(self, fails, warns, goods):
        """Calculate overall security grade."""
        
        total = fails + warns + goods
        if total == 0:
            return "?", "#666666"
        
        if fails == 0 and warns == 0:
            return "A+", "#22c55e"
        elif fails == 0 and warns <= 2:
            return "A", "#4ade80"
        elif fails == 0:
            return "B", "#84cc16"
        elif fails <= 2:
            return "C", "#fbbf24"
        elif fails <= 5:
            return "D", "#fb923c"
        else:
            return "F", "#ef4444"
            
    def _copy_report(self, parsed, host, port, fails, warns, goods):
        """Generate and copy a text report."""
        
        grade, _ = self._calculate_grade(fails, warns, goods)
        
        report = []
        report.append(f"SSH SECURITY AUDIT REPORT")
        report.append(f"Simple SFTP Audit Tool by JDE-Projects")
        report.append(f"=" * 50)
        report.append(f"Host: {host}:{port}")
        report.append(f"Grade: {grade}")
        report.append(f"Summary: {fails} failures, {warns} warnings, {goods} secure")
        report.append(f"")
        
        # Security Checklist
        checklist = self._generate_security_checklist(parsed)
        if checklist:
            report.append("SECURITY CHECKLIST")
            report.append("-" * 18)
            for item in checklist:
                icon = "✓" if item['status'] == 'good' else "✗" if item['status'] == 'bad' else "⚠"
                report.append(f"  {icon} {item['text']}")
            report.append("")
        
        # Server info
        if parsed['software'] or parsed['os']:
            report.append("SERVER INFORMATION")
            report.append("-" * 18)
            if parsed['software']:
                report.append(f"  Software: {parsed['software']}")
            if parsed['os']:
                report.append(f"  OS: {parsed['os']}")
            if parsed['compression']:
                report.append(f"  Compression: {', '.join(parsed['compression'])}")
            report.append("")
        
        # Security issues
        if parsed['security_issues']:
            report.append("⚠️  SECURITY ADVISORIES")
            report.append("-" * 22)
            for issue in parsed['security_issues']:
                report.append(f"  • {issue}")
            report.append("")
        
        sections = [
            ('KEY EXCHANGE ALGORITHMS', 'kex'),
            ('HOST KEY ALGORITHMS', 'key'),
            ('ENCRYPTION CIPHERS', 'enc'),
            ('MESSAGE AUTHENTICATION CODES', 'mac'),
        ]
        
        for title, key in sections:
            if parsed[key]:
                report.append(f"{title}")
                report.append("-" * len(title))
                for alg in parsed[key]:
                    status_icon = "❌" if alg['status'] == 'fail' else "⚠️" if alg['status'] == 'warn' else "✓"
                    size_str = f" ({alg['key_size']}-bit)" if alg.get('key_size') else ""
                    report.append(f"  {status_icon} {alg['name']}{size_str}")
                    if alg['reason']:
                        report.append(f"      {alg['reason']}")
                report.append("")
        
        if parsed['fingerprints']:
            report.append("HOST KEY FINGERPRINTS")
            report.append("-" * 21)
            for fp in parsed['fingerprints']:
                report.append(f"  {fp}")
        
        self.root.clipboard_clear()
        self.root.clipboard_append('\n'.join(report))
    
    def _show_port_error(self):
        """Display an error message for missing port."""
        for widget in self.results_frame.winfo_children():
            widget.destroy()
            
        error_frame = tk.Frame(self.results_frame, bg="#1e1e1e", pady=50)
        error_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(error_frame, text="Please enter a port number", font=("Segoe UI", 16, "bold"),
                fg="#f87171", bg="#1e1e1e").pack()
        
        tk.Label(error_frame, text="Default port for SFTP is 22", font=("Segoe UI", 11),
                fg="#888888", bg="#1e1e1e").pack(pady=(20, 0))
    
    def _show_connection_error(self, host, port):
        """Display a connection error message."""
        for widget in self.results_frame.winfo_children():
            widget.destroy()
            
        error_frame = tk.Frame(self.results_frame, bg="#1e1e1e", pady=50)
        error_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(error_frame, text="Unable to complete audit", font=("Segoe UI", 16, "bold"),
                fg="#f87171", bg="#1e1e1e").pack()
        
        tk.Label(error_frame, text=f"Could not connect to {host}:{port}", font=("Segoe UI", 12),
                fg="#f87171", bg="#1e1e1e").pack(pady=(20, 10))
        
        tk.Label(error_frame, text="Can you reach this SFTP server from this machine and public IP?", 
                font=("Segoe UI", 11), fg="#888888", bg="#1e1e1e").pack()
        
    def _show_error(self, message):
        """Display an error message."""
        for widget in self.results_frame.winfo_children():
            widget.destroy()
            
        error_frame = tk.Frame(self.results_frame, bg="#1e1e1e", pady=50)
        error_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(error_frame, text="❌ Error", font=("Segoe UI", 16, "bold"),
                fg="#f87171", bg="#1e1e1e").pack()
        
        tk.Label(error_frame, text=message, font=("Segoe UI", 11),
                fg="#ffffff", bg="#1e1e1e", wraplength=600).pack(pady=20)
        
    def _audit_complete(self):
        """Called when audit finishes."""
        self.audit_running = False
        self.audit_btn.config(state=tk.NORMAL, bg="#4a9eff")


def check_dependencies():
    """Check if ssh-audit is available."""
    try:
        from ssh_audit.ssh_audit import VERSION
        return True, VERSION
    except ImportError:
        return False, None


def main():
    root = tk.Tk()
    
    # Check for ssh-audit
    available, version = check_dependencies()
    
    if not available:
        result = messagebox.askyesno(
            "ssh-audit Not Found",
            "The ssh-audit library is not installed.\n\n"
            "Would you like instructions on how to build this as a standalone executable?"
        )
        if result:
            messagebox.showinfo(
                "Build Instructions",
                "To create a standalone executable:\n\n"
                "1. Install Python 3.9+ from python.org\n\n"
                "2. Run: pip install ssh-audit pyinstaller\n\n"
                "3. Run: pyinstaller --onefile --windowed --name SimpleSFTPAuditTool simple_sftp_audit.py\n\n"
                "4. Find your exe in the 'dist' folder"
            )
        root.destroy()
        return
    
    app = SSHAuditGUI(root)
    root.mainloop()


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    main()
