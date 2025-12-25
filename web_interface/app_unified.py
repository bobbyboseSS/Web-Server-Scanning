#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified Dirsearch Flask Application
Single Flask application with dirsearch modules integrated directly
No wrapper, no WebSocket - everything embedded within Flask functions
"""

import os
import sys
import json
import time
import threading
import uuid
import signal
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable, Tuple
from flask import Flask, render_template, request, jsonify, send_file
from urllib.parse import urlparse

# Add dirsearch parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import dirsearch core modules
from dirsearch.lib.core.data import options, blacklists
from dirsearch.lib.core.dictionary import Dictionary, get_blacklists
from dirsearch.lib.core.exceptions import (
    CannotConnectException,
    FileExistsException,
    InvalidRawRequest,
    InvalidURLException,
    RequestException,
    SkipTargetInterrupt,
    QuitInterrupt,
)
from dirsearch.lib.core.logger import logger
from dirsearch.lib.core.settings import (
    BANNER,
    DEFAULT_HEADERS,
    SCRIPT_PATH,
    NEW_LINE,
    STANDARD_PORTS,
    UNKNOWN,
)
from dirsearch.lib.connection.requester import Requester, AsyncRequester, BaseRequester
from dirsearch.lib.connection.response import BaseResponse
from dirsearch.lib.core.fuzzer import Fuzzer, AsyncFuzzer, BaseFuzzer
from dirsearch.lib.core.scanner import Scanner, AsyncScanner, BaseScanner
from dirsearch.lib.parse.config import ConfigParser
from dirsearch.lib.parse.cmdline import parse_arguments
from dirsearch.lib.parse.headers import HeadersParser
from dirsearch.lib.parse.rawrequest import parse_raw
from dirsearch.lib.parse.url import clean_path, parse_path
from dirsearch.lib.report.manager import ReportManager
from dirsearch.lib.utils.common import (
    get_readable_size,
    lstrip_once,
    strip_and_uniquify,
    iprange,
    read_stdin,
)
from dirsearch.lib.utils.file import FileUtils
from dirsearch.lib.utils.schemedet import detect_scheme
from dirsearch.lib.utils.mimetype import guess_mimetype

app = Flask(__name__)
app.secret_key = 'dirsearch_unified_app_secret_key_2025'

# Global scan storage
active_scans: Dict[str, 'UnifiedScanner'] = {}
scan_history: List[Dict[str, Any]] = []
scan_results: Dict[str, List[Dict[str, Any]]] = {}

class UnifiedScanner:
    """Unified scanner with all dirsearch functionality embedded"""
    
    def __init__(self, scan_id: str, config: Dict[str, Any]):
        self.scan_id = scan_id
        self.config = config
        self.status = "initializing"
        self.progress = 0
        self.results = []
        self.start_time = None
        self.end_time = None
        self.error = None
        self.fuzzer = None
        self.requester = None
        self.dictionary = None
        self.base_path = ""
        self.url = ""
        self.passed_urls = set()
        self.directories = []
        self.jobs_processed = 0
        self.errors = 0
        self.consecutive_errors = 0
        self.should_stop = False
        
    def setup_options_function(self):
        """Setup dirsearch options from web config - embedded function"""
        # Clear existing options
        options.clear()
        
        # Set basic options from config
        options["urls"] = [self.config["url"]]
        options["http_method"] = self.config.get("http_method", "GET").upper()
        options["extensions"] = tuple(self.config.get("extensions", "php,asp,aspx,jsp,html").split(","))
        options["wordlists"] = self.config.get("wordlist", "db/dicc.txt")
        options["thread_count"] = int(self.config.get("threads", 25))
        options["timeout"] = int(self.config.get("timeout", 10))
        options["delay"] = float(self.config.get("delay", 0))
        options["max_retries"] = int(self.config.get("max_retries", 1))
        options["recursive"] = self.config.get("recursive", False)
        options["recursion_depth"] = int(self.config.get("max_depth", 0))
        options["subdirs"] = self.config.get("subdirs", ["/"])
        
        # Headers
        web_headers = self.config.get("headers", {})
        if not web_headers:
            web_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        options["headers"] = {**DEFAULT_HEADERS, **web_headers}
        
        # Filtering options
        exclude_status = self.config.get("exclude_status_codes", [])
        if isinstance(exclude_status, str):
            exclude_status = [int(x.strip()) for x in exclude_status.split(",") if x.strip()]
        options["exclude_status_codes"] = set(exclude_status)
        
        include_status = self.config.get("include_status_codes", [])
        if isinstance(include_status, str):
            include_status = [int(x.strip()) for x in include_status.split(",") if x.strip()]
        options["include_status_codes"] = set(include_status)
        
        exclude_sizes = self.config.get("exclude_sizes", [])
        if isinstance(exclude_sizes, str):
            exclude_sizes = [int(x.strip()) for x in exclude_sizes.split(",") if x.strip()]
        options["exclude_sizes"] = set(exclude_sizes)
        
        options["exclude_texts"] = self.config.get("exclude_texts", [])
        options["exclude_regex"] = self.config.get("exclude_regex", [])
        
        # Proxy settings
        if self.config.get("proxy"):
            options["proxies"] = [self.config["proxy"]]
        else:
            options["proxies"] = []
            
        # Data settings
        if self.config.get("data"):
            options["data"] = self.config["data"]
            
        # Other settings
        options["async_mode"] = self.config.get("async_mode", False)
        options["follow_redirects"] = self.config.get("follow_redirects", False)
        options["max_time"] = int(self.config.get("max_time", 0))
        options["target_max_time"] = int(self.config.get("target_max_time", 0))
        
        # Output settings (disable for web interface)
        options["output_formats"] = []
        options["output_file"] = None
        options["quiet"] = True
        options["disable_cli"] = True
        
    def setup_dictionary_function(self):
        """Setup dictionary functionality - embedded function"""
        try:
            # Setup blacklists
            blacklists.update(get_blacklists())
            
            # Setup dictionary
            wordlist_path = options["wordlists"]
            if not os.path.isabs(wordlist_path):
                wordlist_path = os.path.join(SCRIPT_PATH, wordlist_path)
            self.dictionary = Dictionary(files=[wordlist_path])
            
        except Exception as e:
            self.error = str(e)
            self.status = "error"
            raise
            
    def setup_requester_function(self):
        """Setup HTTP requester - embedded function"""
        try:
            # Setup requester
            if options["async_mode"]:
                self.requester = AsyncRequester()
            else:
                self.requester = Requester()
                
        except Exception as e:
            self.error = str(e)
            self.status = "error"
            raise
            
    def setup_fuzzer_function(self):
        """Setup fuzzer with callbacks - embedded function"""
        try:
            # Setup callbacks
            match_callbacks = (self.match_callback_function, self.save_result_callback_function, self.reset_consecutive_errors_function)
            not_found_callbacks = (self.update_progress_callback_function, self.reset_consecutive_errors_function)
            error_callbacks = (self.error_callback_function, self.append_error_log_function)
            
            # Setup fuzzer
            if options["async_mode"]:
                self.fuzzer = AsyncFuzzer(
                    self.requester,
                    self.dictionary,
                    match_callbacks=match_callbacks,
                    not_found_callbacks=not_found_callbacks,
                    error_callbacks=error_callbacks,
                )
            else:
                self.fuzzer = Fuzzer(
                    self.requester,
                    self.dictionary,
                    match_callbacks=match_callbacks,
                    not_found_callbacks=not_found_callbacks,
                    error_callbacks=error_callbacks,
                )
                
        except Exception as e:
            self.error = str(e)
            self.status = "error"
            raise
            
    def set_target_function(self, url: str):
        """Set target URL and prepare directories - embedded function"""
        try:
            # Validate and clean URL
            if not url.startswith(("http://", "https://")):
                scheme = detect_scheme(url, options["timeout"])
                url = f"{scheme}://{url}"
                
            self.url = url
            parsed = urlparse(url)
            
            # Set base path
            self.base_path = parsed.path or "/"
            
            # Setup directories for scanning
            self.directories = []
            for subdir in options["subdirs"]:
                if not subdir.startswith("/"):
                    subdir = "/" + subdir
                self.directories.append(self.base_path + subdir)
                
        except Exception as e:
            raise InvalidURLException(str(e))
            
    def match_callback_function(self, response: BaseResponse):
        """Callback for found paths - embedded function"""
        if self.should_stop:
            return
            
        result = {
            "url": response.url,
            "path": response.path,
            "status": response.status,
            "size": len(response.content) if response.content else 0,
            "content_type": response.headers.get("content-type", ""),
            "timestamp": datetime.now().isoformat()
        }
        self.results.append(result)
        scan_results[self.scan_id] = self.results.copy()
        
    def save_result_callback_function(self, response: BaseResponse):
        """Save result callback - embedded function"""
        # Minimal implementation for web interface
        pass
        
    def update_progress_callback_function(self, response: BaseResponse):
        """Progress update callback - embedded function"""
        if self.should_stop:
            return
            
        if hasattr(self.dictionary, '_index') and hasattr(self.dictionary, '__len__'):
            try:
                self.progress = int((self.dictionary._index / len(self.dictionary)) * 100)
            except (ZeroDivisionError, AttributeError):
                self.progress = min(self.progress + 1, 99)
        else:
            self.progress = min(self.progress + 1, 99)
            
    def error_callback_function(self, exception: RequestException):
        """Error callback - embedded function"""
        if self.should_stop:
            return
        self.errors += 1
        self.consecutive_errors += 1
        
    def append_error_log_function(self, exception: RequestException):
        """Error logging callback - embedded function"""
        logger.exception(exception)
        
    def reset_consecutive_errors_function(self, response: BaseResponse):
        """Reset consecutive error counter - embedded function"""
        self.consecutive_errors = 0
        
    def execute_scan_function(self):
        """Main scan execution - embedded function"""
        try:
            self.status = "running"
            self.start_time = datetime.now()
            
            # Setup all components
            self.setup_options_function()
            self.setup_dictionary_function()
            self.setup_requester_function()
            self.setup_fuzzer_function()
            
            # Set target
            self.set_target_function(options["urls"][0])
            
            # Start scanning directories
            while self.directories and not self.should_stop:
                try:
                    current_directory = self.directories[0]
                    
                    # Set base path for fuzzer
                    self.fuzzer.set_base_path(current_directory)
                    
                    # Start scanning
                    if options["async_mode"]:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            loop.run_until_complete(self.fuzzer.start())
                        finally:
                            loop.close()
                    else:
                        self.fuzzer.start()
                        
                except (KeyboardInterrupt, asyncio.CancelledError):
                    break
                except Exception as e:
                    self.error = str(e)
                    logger.exception(e)
                finally:
                    # Reset dictionary for next directory
                    self.dictionary.reset()
                    self.directories.pop(0)
                    self.jobs_processed += 1
                    
            if not self.should_stop:
                self.status = "completed"
                self.progress = 100
            else:
                self.status = "stopped"
                
        except Exception as e:
            self.error = str(e)
            self.status = "error"
            logger.exception(e)
        finally:
            self.end_time = datetime.now()
            # Update scan in storage
            if self.scan_id in active_scans:
                active_scans[self.scan_id] = self
                
    def stop_scan_function(self):
        """Stop scan function - embedded function"""
        self.should_stop = True
        self.status = "stopping"
        if self.fuzzer:
            if hasattr(self.fuzzer, 'stop'):
                self.fuzzer.stop()
        self.status = "stopped"
        self.end_time = datetime.now()

# Flask Routes
@app.route('/')
def index_function():
    """Main dashboard - embedded function"""
    return render_template('index.html')

@app.route('/scan')
def scan_page_function():
    """Scan configuration page - embedded function"""
    return render_template('scan.html')

@app.route('/history')
def history_page_function():
    """Scan history page - embedded function"""
    return render_template('history.html')

@app.route('/config')
def config_page_function():
    """Configuration page - embedded function"""
    return render_template('config.html')

# API Routes - all embedded functions
@app.route('/api/scan/start', methods=['POST'])
def start_scan_function():
    """Start scan API - embedded function"""
    try:
        config = request.get_json()
        
        # Validate required fields
        if not config.get("url"):
            return jsonify({
                "status": "error",
                "message": "URL is required"
            }), 400
            
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scanner instance
        scanner = UnifiedScanner(scan_id, config)
        active_scans[scan_id] = scanner
        
        # Start scan in background thread
        scan_thread = threading.Thread(target=scanner.execute_scan_function)
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({
            "status": "success",
            "scan_id": scan_id,
            "message": "Scan started successfully"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/scan/status/<scan_id>', methods=['GET'])
def get_scan_status_function(scan_id):
    """Get scan status API - embedded function"""
    if scan_id not in active_scans:
        return jsonify({"status": "error", "message": "Scan not found"}), 404
        
    scanner = active_scans[scan_id]
    
    response = {
        "status": scanner.status,
        "progress": scanner.progress,
        "results_count": len(scanner.results),
        "start_time": scanner.start_time.isoformat() if scanner.start_time else None,
        "end_time": scanner.end_time.isoformat() if scanner.end_time else None,
        "error": scanner.error,
        "url": scanner.url,
        "jobs_processed": scanner.jobs_processed,
        "errors": scanner.errors
    }
    
    return jsonify(response)

@app.route('/api/scan/results/<scan_id>', methods=['GET'])
def get_scan_results_function(scan_id):
    """Get scan results API - embedded function"""
    if scan_id not in scan_results and scan_id not in active_scans:
        return jsonify({"status": "error", "message": "Results not found"}), 404
        
    results = scan_results.get(scan_id, [])
    if scan_id in active_scans:
        results = active_scans[scan_id].results
        
    return jsonify({
        "status": "success",
        "results": results
    })

@app.route('/api/scan/stop/<scan_id>', methods=['POST'])
def stop_scan_function(scan_id):
    """Stop scan API - embedded function"""
    if scan_id not in active_scans:
        return jsonify({"status": "error", "message": "Scan not found"}), 404
        
    scanner = active_scans[scan_id]
    scanner.stop_scan_function()
    
    return jsonify({
        "status": "success",
        "message": "Scan stopped"
    })

@app.route('/api/scan/list', methods=['GET'])
def list_scans_function():
    """List all scans API - embedded function"""
    scans = []
    
    for scan_id, scanner in active_scans.items():
        scan_info = {
            "scan_id": scan_id,
            "status": scanner.status,
            "progress": scanner.progress,
            "results_count": len(scanner.results),
            "start_time": scanner.start_time.isoformat() if scanner.start_time else None,
            "end_time": scanner.end_time.isoformat() if scanner.end_time else None,
            "url": scanner.url,
            "error": scanner.error,
            "jobs_processed": scanner.jobs_processed,
            "errors": scanner.errors
        }
        scans.append(scan_info)
        
    return jsonify({
        "status": "success",
        "scans": scans
    })

@app.route('/api/scan/delete/<scan_id>', methods=['DELETE'])
def delete_scan_function(scan_id):
    """Delete scan API - embedded function"""
    if scan_id in active_scans:
        del active_scans[scan_id]
        
    if scan_id in scan_results:
        del scan_results[scan_id]
        
    return jsonify({
        "status": "success",
        "message": "Scan deleted"
    })

@app.route('/api/wordlists', methods=['GET'])
def get_wordlists_function():
    """Get wordlists API - embedded function"""
    wordlists_dir = os.path.join(SCRIPT_PATH, "db")
    
    if not os.path.exists(wordlists_dir):
        return jsonify({"status": "error", "message": "Wordlists directory not found"}), 404
        
    wordlists = []
    for file in os.listdir(wordlists_dir):
        if file.endswith('.txt'):
            file_path = os.path.join(wordlists_dir, file)
            wordlists.append({
                "name": file,
                "path": file_path,
                "size": os.path.getsize(file_path)
            })
            
    return jsonify({
        "status": "success",
        "wordlists": wordlists
    })

@app.route('/api/config', methods=['GET'])
def get_config_function():
    """Get configuration API - embedded function"""
    return jsonify({
        "status": "success",
        "config": dict(options)
    })

@app.route('/api/config', methods=['POST'])
def save_config_function():
    """Save configuration API - embedded function"""
    try:
        config = request.get_json()
        # Update options with new config (only safe options)
        safe_keys = [
            "thread_count", "timeout", "delay", "max_retries", "recursive",
            "recursion_depth", "follow_redirects", "max_time", "target_max_time"
        ]
        
        for key, value in config.items():
            if key in safe_keys:
                options[key] = value
            
        return jsonify({
            "status": "success",
            "message": "Configuration saved"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    # Initialize blacklists
    try:
        blacklists.update(get_blacklists())
    except Exception as e:
        print(f"Warning: Could not load blacklists: {e}")
        
    print("Starting Unified Dirsearch Web Interface...")
    print("Access the application at: http://localhost:5000")
    print("This version has all dirsearch modules embedded within Flask functions")
    
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
