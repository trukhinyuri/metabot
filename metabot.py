#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Metabot: An autonomous programming assistant.

This module implements a sophisticated bot that can process programming tasks
autonomously using OpenAI's API. It monitors a file for new tasks, processes them
through multiple phases (analysis, implementation, testing, optimization),
and provides detailed progress reporting.

Author: Yuri Trukhin <yuri@trukhin.com>
License: Apache License 2.0
"""

# Copyright 2025 Yuri Trukhin
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import logging
import json
import time
import signal
import sys
import hashlib
import traceback
import asyncio
from datetime import datetime, timezone
from typing import Dict, Optional, List, Any, Tuple
import queue
import threading
import concurrent.futures
from rich.console import Console
from rich.theme import Theme
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from openai import OpenAI
from agents import Agent, function_tool, Runner
from agents.run import RunConfig
from cryptography.fernet import Fernet

# Store the original script directory before changing working directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Set working directory to the parent directory
os.chdir(os.path.join(os.path.dirname(__file__), '..'))

# Directory for storing metabot configuration, logs, and state
METABOT_DIR = ".metabot"

# Configure rich console with custom theme for better visual output
custom_theme = Theme({
    "success": "bold green",
    "error": "bold red",
    "info": "cyan",
    "warning": "yellow",
    "highlight": "bold magenta"
})
console = Console(theme=custom_theme)

# Setup logging with rotation to prevent excessive log file sizes
os.makedirs(os.path.join(METABOT_DIR, "logs"), exist_ok=True)
logger = logging.getLogger('metabot')
logger.setLevel(logging.DEBUG)

class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging.

    This formatter converts log records into JSON format for better parsing
    and analysis by log management tools.
    """
    def format(self, record):
        """Format the log record as a JSON string.

        Args:
            record: The log record to format

        Returns:
            A JSON string representation of the log record
        """
        return json.dumps({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'message': record.msg,
            'context': getattr(record, 'context', {})
        }, ensure_ascii=False)

# Configure file handler with rotation (5MB max size, keep 3 backups)
handler = logging.handlers.RotatingFileHandler(
    os.path.join(METABOT_DIR, "logs", "metabot.log"),
    maxBytes=5*1024*1024,
    backupCount=3
)
handler.setFormatter(JsonFormatter())
logger.addHandler(handler)

# Configure console handler with simple format
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(console_handler)

# Global variables for state management
stop_requested = False  # Flag to signal shutdown
state_lock = threading.Lock()  # Lock for thread-safe state access
task_queue = queue.Queue()  # Queue for pending tasks
progress_data = {}  # Store progress information
progress_lock = threading.Lock()  # Lock for thread-safe progress updates

# Constants for timeouts and retries
DEFAULT_COMMAND_TIMEOUT = 30  # seconds
MAX_COMMAND_TIMEOUT = 300  # seconds (5 minutes)
MAX_RETRIES = 3  # Maximum number of retry attempts
RETRY_DELAY = 2  # seconds between retry attempts

def signal_handler(sig, frame):
    """Handle termination signals gracefully.

    This function is called when the process receives SIGINT (Ctrl+C) or SIGTERM signals.
    It sets the stop_requested flag to True, which will cause the main loop to exit cleanly.

    Args:
        sig: Signal number
        frame: Current stack frame
    """
    global stop_requested
    logger.info("Stop signal received.", extra={'context': {'signal': sig}})
    console.print("[error]🛑 Stopping Metabot[/error]")
    stop_requested = True

# Register signal handlers for graceful termination
signal.signal(signal.SIGINT, signal_handler)   # Handle keyboard interrupt (Ctrl+C)
signal.signal(signal.SIGTERM, signal_handler)  # Handle termination signal

# File paths for communication and state persistence
ASK_FILE = os.path.join(METABOT_DIR, "ask.txt")        # Input file for new tasks
ANSWER_FILE = os.path.join(METABOT_DIR, "answer.txt")  # Output file for task results
STATE_FILE = os.path.join(METABOT_DIR, "state", "state.json")  # State persistence file


def load_config() -> Dict:
    """Load configuration from JSON file with optional decryption support.

    This function attempts to load the configuration from several possible locations:
    1. First from the script directory
    2. Then from the .metabot directory
    3. Finally from the root directory (copying it to .metabot if found)

    If encrypted values are present in the config and an encryption key is provided,
    those values will be decrypted automatically.

    Returns:
        Dict: The loaded and decrypted configuration

    Raises:
        FileNotFoundError: If no config.json file can be found in any location
    """
    # Debug: Print current working directory and list files
    print(f"Current working directory: {os.getcwd()}")
    print(f"Script directory: {SCRIPT_DIR}")
    print(f"Files in script directory: {os.listdir(SCRIPT_DIR)}")

    # Define possible config file locations
    config_path = os.path.join(METABOT_DIR, "config.json")
    script_config_path = os.path.join(SCRIPT_DIR, "config.json")

    print(f"Looking for config at: {config_path}")
    print(f"Looking for config at: {script_config_path}")

    # Try loading from script directory first (highest priority)
    if os.path.exists(script_config_path):
        print(f"Found config.json in script directory: {script_config_path}")
        with open(script_config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        return config

    # If not in script directory, try copying from root to .metabot
    if not os.path.exists(config_path) and os.path.exists("config.json"):
        print("Found config.json in root directory, copying to .metabot")
        # Create .metabot directory if it doesn't exist
        os.makedirs(METABOT_DIR, exist_ok=True)
        # Copy the config file
        with open("config.json", "r", encoding="utf-8") as src:
            config_content = src.read()
        with open(config_path, "w", encoding="utf-8") as dst:
            dst.write(config_content)
        logger.info(f"Copied config.json from root to {METABOT_DIR} directory")

    # If still not found, raise an error
    if not os.path.exists(config_path):
        print(f"Config not found at {config_path} or {script_config_path}")
        raise FileNotFoundError("config.json is missing")

    # Load the config file
    print(f"Loading config from {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    # Handle encrypted values if present
    if 'encrypted_keys' in config and config['encrypted_keys']:
        encryption_key = config.get('encryption_key', "")
        if encryption_key:
            cipher = Fernet(encryption_key.encode())
            for key in config['encrypted_keys']:
                if key in config and config[key]:
                    config[key] = cipher.decrypt(config[key].encode()).decode()

    return config

# Load configuration and initialize OpenAI client
config = load_config()
os.environ["OPENAI_API_KEY"] = config["openai_api_key"]
client = OpenAI(api_key=config["openai_api_key"])

# Define function tools for the agent
@function_tool
def web_search(query: str) -> str:
    """Perform a web search using Brave Search API.

    This function sends a search query to the Brave Search API and returns
    the top 5 results with their titles and descriptions.

    Args:
        query: The search query string

    Returns:
        A string containing the search results or an error message
    """
    api_key = config.get("brave_search_api_key", "")
    if not api_key:
        return "Brave Search API key not provided."

    try:
        import requests
        url = "https://api.search.brave.com/res/v1/web/search"
        headers = {"Accept": "application/json", "X-Subscription-Token": api_key}
        params = {"q": query}

        # Send request with timeout to prevent hanging
        response = requests.get(url, headers=headers, params=params, timeout=10)
        data = response.json()
        results = data.get("web", {}).get("results", [])

        # Format the results as a string with title and description
        return "\n".join([f"{r['title']}: {r['description']}" for r in results[:5]])
    except Exception as e:
        return f"Error performing web search: {str(e)}"

@function_tool
def browse_page(url: str, query: str) -> str:
    """Extract relevant content from a webpage.

    This function fetches a webpage, parses its HTML content, and extracts
    paragraphs that contain the specified query string.

    Args:
        url: The URL of the webpage to browse
        query: The text to search for in the page content

    Returns:
        A string containing up to 3 relevant paragraphs or an error message
    """
    try:
        import requests
        from bs4 import BeautifulSoup

        # Fetch the webpage with timeout
        response = requests.get(url, timeout=10)

        # Parse HTML and extract paragraphs
        soup = BeautifulSoup(response.text, 'html.parser')
        paragraphs = soup.find_all('p')

        # Filter paragraphs containing the query (case-insensitive)
        relevant = [p.get_text() for p in paragraphs if query.lower() in p.get_text().lower()]

        # Return up to 3 relevant paragraphs or a message if none found
        return "\n\n".join(relevant[:3]) if relevant else "Relevant content not found."
    except Exception as e:
        return f"Error browsing page: {str(e)}"

@function_tool
def write_file(path: str, content: str) -> str:
    """Write content to a file.

    This function creates or overwrites a file with the specified content.
    It ensures proper UTF-8 encoding for text files.

    Args:
        path: The path to the file to write
        content: The content to write to the file

    Returns:
        A success message or an error message
    """
    try:
        # Create parent directories if they don't exist
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

        # Write content to file with UTF-8 encoding
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"File written: {path}"
    except Exception as e:
        return f"Error writing file: {str(e)}"

@function_tool
def read_file(path: str) -> str:
    """Read content from a file.

    This function reads and returns the content of a text file.
    It assumes UTF-8 encoding for text files.

    Args:
        path: The path to the file to read

    Returns:
        The file content as a string or an error message
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"

@function_tool
def list_files(directory: str) -> str:
    """List files in a directory.

    This function returns a list of all files and directories in the specified path.
    If no directory is specified, it lists the current directory.

    Args:
        directory: The directory path to list (defaults to current directory if empty)

    Returns:
        A newline-separated list of files and directories or an error message
    """
    if not directory:
        directory = "."
    try:
        files = os.listdir(directory)
        return "\n".join(files)
    except Exception as e:
        return f"Error listing files: {str(e)}"

@function_tool
def run_command(command: str, timeout: int) -> str:
    """Run a shell command and return its output.

    This function executes a shell command with a specified timeout and
    captures its output. It updates progress information during execution.

    Args:
        command: The shell command to execute
        timeout: Maximum execution time in seconds

    Returns:
        The command's stdout output if successful, or an error message
    """
    import subprocess
    try:
        # Update progress and log the command execution
        update_progress("command", f"Running command: {command}", 0)

        # Enforce maximum timeout limit for safety
        actual_timeout = min(timeout, MAX_COMMAND_TIMEOUT)

        # Execute the command with timeout
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=actual_timeout
        )

        # Update progress on completion
        update_progress("command", f"Command completed: {command}", 100)

        # Return stdout if successful, stderr if failed
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        # Handle timeout case
        update_progress("command", f"Command timed out: {command}", 100, error=True)
        return f"Error: Command timed out after {actual_timeout} seconds"
    except Exception as e:
        # Handle other exceptions
        update_progress("command", f"Command failed: {command}", 100, error=True)
        return f"Error running command: {str(e)}"

def execute_command(command: str, timeout: int = DEFAULT_COMMAND_TIMEOUT, retries: int = MAX_RETRIES) -> str:
    """Run a shell command with retry logic.

    This function is a non-tool version of run_command that adds retry capability.
    It will attempt to run the command multiple times if it fails.

    Args:
        command: The shell command to execute
        timeout: Maximum execution time in seconds (default: DEFAULT_COMMAND_TIMEOUT)
        retries: Maximum number of retry attempts (default: MAX_RETRIES)

    Returns:
        The command's stdout output if successful, or an error message
    """
    import subprocess

    # Try the command up to 'retries' times
    for attempt in range(retries):
        try:
            # Update progress with attempt information
            update_progress("command", f"Running command (attempt {attempt+1}/{retries}): {command}", 0)

            # Enforce maximum timeout limit
            actual_timeout = min(timeout, MAX_COMMAND_TIMEOUT)

            # Execute the command
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=actual_timeout
            )

            # Update progress on completion
            update_progress("command", f"Command completed: {command}", 100)

            # Return stdout if successful
            if result.returncode == 0:
                return result.stdout
            else:
                # Handle command execution failure
                error_msg = f"Error (attempt {attempt+1}/{retries}): {result.stderr}"
                update_progress("command", error_msg, 100, error=True)

                # Retry if attempts remain
                if attempt < retries - 1:
                    time.sleep(RETRY_DELAY)
                else:
                    return error_msg
        except subprocess.TimeoutExpired:
            # Handle timeout case
            error_msg = f"Error (attempt {attempt+1}/{retries}): Command timed out after {actual_timeout} seconds"
            update_progress("command", error_msg, 100, error=True)

            # Retry if attempts remain
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
            else:
                return error_msg
        except Exception as e:
            # Handle other exceptions
            error_msg = f"Error running command (attempt {attempt+1}/{retries}): {str(e)}"
            update_progress("command", error_msg, 100, error=True)

            # Retry if attempts remain
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
            else:
                return error_msg

    return "All retry attempts failed"

@function_tool
def analyze_code(file_path: str) -> str:
    """Analyze code for potential issues and optimization opportunities."""
    try:
        update_progress("analysis", f"Analyzing code: {file_path}", 0)
        if not os.path.exists(file_path):
            update_progress("analysis", f"File not found: {file_path}", 100, error=True)
            return f"Error: File not found: {file_path}"
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()
        analysis_results = []
        pylint_result = execute_command(f"pylint {file_path}", timeout=60)
        if not pylint_result.startswith("Error"):
            analysis_results.append(f"Pylint analysis:\n{pylint_result}")
        flake8_result = execute_command(f"flake8 {file_path}", timeout=30)
        if not flake8_result.startswith("Error"):
            analysis_results.append(f"Flake8 analysis:\n{flake8_result}")
        if not analysis_results:
            lines = code.split("\n")
            analysis_results.append(f"Basic analysis:\n- File has {len(lines)} lines of code")
            if "import *" in code:
                analysis_results.append("- Warning: Found wildcard imports")
            if "except:" in code and "except Exception:" not in code:
                analysis_results.append("- Warning: Found bare except clauses")
            if "print(" in code:
                analysis_results.append("- Note: Found print statements, consider using logging")
        update_progress("analysis", f"Analysis completed: {file_path}", 100)
        return "\n\n".join(analysis_results)
    except Exception as e:
        update_progress("analysis", f"Analysis failed: {file_path}", 100, error=True)
        return f"Error analyzing code: {str(e)}"

@function_tool
def optimize_code(file_path: str, suggestions: str) -> str:
    """Apply optimization suggestions to code."""
    try:
        update_progress("optimization", f"Optimizing code: {file_path}", 0)
        if not os.path.exists(file_path):
            update_progress("optimization", f"File not found: {file_path}", 100, error=True)
            return f"Error: File not found: {file_path}"
        with open(file_path, "r", encoding="utf-8") as f:
            original_code = f.read()
        backup_path = f"{file_path}.bak"
        with open(backup_path, "w", encoding="utf-8") as f:
            f.write(original_code)
        update_progress("optimization", f"Created backup: {backup_path}", 50)
        update_progress("optimization", f"Optimization completed: {file_path}", 100)
        return f"Code optimization suggestions for {file_path}:\n{suggestions}\n\nA backup was created at {backup_path}"
    except Exception as e:
        update_progress("optimization", f"Optimization failed: {file_path}", 100, error=True)
        return f"Error optimizing code: {str(e)}"

def update_progress(task_type: str, message: str, percentage: int, error: bool = False):
    """Update progress information for display.

    This function records progress information for a task, which can be displayed
    to the user. It uses a thread-safe approach to update the shared progress_data
    dictionary.

    Args:
        task_type: Category of the task (e.g., "command", "analysis")
        message: Description of the current progress state
        percentage: Completion percentage (0-100)
        error: Whether this update represents an error state
    """
    # Use lock to ensure thread-safety when updating shared progress data
    with progress_lock:
        # Create timestamp for this progress update
        timestamp = datetime.now(timezone.utc).isoformat()

        # Store progress information
        progress_data[timestamp] = {
            "task_type": task_type,
            "message": message,
            "percentage": percentage,
            "error": error,
            "timestamp": timestamp
        }

        # Limit the size of progress_data to prevent memory issues
        # by removing the oldest entries when we exceed 100 items
        if len(progress_data) > 100:
            oldest = sorted(progress_data.keys())[0]
            del progress_data[oldest]

@function_tool
def generate_code(file_path: str, requirements: str) -> str:
    """Generate code based on requirements and save it to the specified file."""
    try:
        update_progress("generation", f"Generating code for: {file_path}", 0)
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                existing_code = f.read()
            backup_path = f"{file_path}.bak"
            with open(backup_path, "w", encoding="utf-8") as f:
                f.write(existing_code)
            update_progress("generation", f"Created backup: {backup_path}", 20)
        update_progress("generation", f"Code generation completed: {file_path}", 100)
        return f"Code generation for {file_path} based on requirements:\n{requirements}\n\nPlease implement the code in the next step."
    except Exception as e:
        update_progress("generation", f"Code generation failed: {file_path}", 100, error=True)
        return f"Error generating code: {str(e)}"

@function_tool
def test_code(file_path: str, test_type: str) -> str:
    """Test code using appropriate testing framework. Specify test_type, e.g., 'unit' or 'lint'."""
    try:
        update_progress("testing", f"Testing code: {file_path}", 0)
        if not os.path.exists(file_path):
            update_progress("testing", f"File not found: {file_path}", 100, error=True)
            return f"Error: File not found: {file_path}"
        test_command = None
        if file_path.endswith(".py"):
            if test_type.lower() == "unit":
                test_command = f"pytest {file_path} -v"
            elif test_type.lower() == "lint":
                test_command = f"pylint {file_path}"
        if not test_command:
            update_progress("testing", f"Unsupported test type: {test_type} for {file_path}", 100, error=True)
            return f"Error: Unsupported test type: {test_type} for {file_path}"
        test_result = execute_command(test_command, timeout=60)
        update_progress("testing", f"Testing completed: {file_path}", 100)
        return f"Test results for {file_path} ({test_type}):\n{test_result}"
    except Exception as e:
        update_progress("testing", f"Testing failed: {file_path}", 100, error=True)
        return f"Error testing code: {str(e)}"

@function_tool
def get_progress() -> str:
    """Get the current progress information."""
    with progress_lock:
        if not progress_data:
            return "No progress data available."
        recent_updates = sorted(progress_data.items(), reverse=True)[:10]
        formatted_updates = []
        for _, update in recent_updates:
            status = "❌ " if update["error"] else "✅ " if update["percentage"] == 100 else "🔄 "
            formatted_updates.append(f"{status}[{update['task_type']}] {update['message']} ({update['percentage']}%)")
        return "\n".join(formatted_updates)

agent = Agent(
    name="Metabot",
    instructions="""You are an autonomous programming assistant tasked with developing high-quality software solutions. 
Your goal is to write code that not only works but is optimized, maintainable, and follows best practices.

CAPABILITIES:
- You can search the web for information
- You can read, write, and analyze code files
- You can run commands to test and validate your solutions
- You can optimize existing code
- You can generate new code based on requirements
- You can work autonomously to solve complex programming tasks

APPROACH:
1. Break down complex tasks into smaller, manageable steps
2. Research and gather information before coding
3. Write clean, well-documented code
4. Test your code thoroughly using test_code with an appropriate test_type (e.g., 'unit' or 'lint')
5. Optimize your code for performance and maintainability
6. Document your process and decisions

When using tools, ensure all required parameters are provided as defaults are not allowed.
When faced with a programming task:
- First analyze the requirements thoroughly
- Research any unfamiliar concepts or technologies
- Plan your approach before writing code
- Implement your solution step by step
- Test each component as you build it
- Refactor and optimize your code
- Document your code and provide usage examples

Always show your work and explain your reasoning. If you encounter issues, try to solve them independently before asking for help.
Use the get_progress tool to check on the status of ongoing tasks.
""",
    tools=[
        web_search,
        browse_page,
        write_file,
        read_file,
        list_files,
        run_command,
        analyze_code,
        optimize_code,
        generate_code,
        test_code,
        get_progress
    ]
)

def load_state() -> Dict:
    default = {"iteration": 0, "current_task": None, "task_completed": False}
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
        default.update(state)
    return default

def save_state(state: Dict):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

def write_answer(message: str):
    os.makedirs(METABOT_DIR, exist_ok=True)
    with open(ANSWER_FILE, "w", encoding="utf-8") as f:
        f.write(message)

class AskFileHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_modified(self, event):
        if event.src_path == ASK_FILE:
            self.callback()

def start_watching_ask_file(callback):
    event_handler = AskFileHandler(callback)
    observer = Observer()
    observer.schedule(event_handler, path=METABOT_DIR, recursive=False)
    observer.start()
    console.print(f"[success]✅ Started monitoring {ASK_FILE}[/success]")
    return observer

def handle_new_task():
    with state_lock:
        state = load_state()
        if os.path.exists(ASK_FILE):
            with open(ASK_FILE, "r", encoding="utf-8") as f:
                task = f.read().strip()
            if task:
                task_queue.put(task)
                state["current_task"] = task
                state["task_completed"] = False
                save_state(state)
                console.print(f"[success]✅ New task added: {task[:100]}...[/success]")
            else:
                console.print("[info]ℹ️ No task in ask.txt.[/info]")

def display_progress_panel():
    """Display a panel with current progress information."""
    with progress_lock:
        if not progress_data:
            return Panel("No progress data available", title="Metabot Progress", border_style="blue")
        recent_updates = sorted(progress_data.items(), reverse=True)[:10]
        formatted_updates = []
        for _, update in recent_updates:
            status = "❌ " if update["error"] else "✅ " if update["percentage"] == 100 else "🔄 "
            formatted_updates.append(f"{status}[{update['task_type']}] {update['message']} ({update['percentage']}%)")
        return Panel("\n".join(formatted_updates), title="Metabot Progress", border_style="blue")

def process_task(task: str):
    """Process a task with autonomous programming capabilities and detailed progress reporting.

    This function sets up a new asyncio event loop in the worker thread to ensure that
    Runner.run_sync can properly function in a threaded environment. The event loop is
    properly cleaned up after the task is completed or if an exception occurs.

    Args:
        task (str): The task description to process
    """
    # Check for maximum recovery depth to prevent infinite loops
    max_recovery_depth = 3
    error_prefix = "There was an error processing the task: "
    depth = 0
    temp_task = task
    while temp_task.startswith(error_prefix):
        depth += 1
        temp_task = temp_task[len(error_prefix):].strip("'")
        if depth > max_recovery_depth:
            error_msg = f"Maximum recovery depth of {max_recovery_depth} reached. Stopping further processing."
            update_progress("task", error_msg, 100, error=True)
            write_answer(error_msg)
            console.print(f"[error]❌ {error_msg}[/error]")
            return

    with state_lock:
        state = load_state()
        state["iteration"] += 1
        save_state(state)

    task_id = hashlib.md5(f"{task}-{state['iteration']}".encode()).hexdigest()
    update_progress("task", f"Starting task (iteration {state['iteration']}): {task[:100]}...", 0)
    console.print(f"[info]📋 Processing task (iteration {state['iteration']}): {task[:100]}...[/info]")
    write_answer("Processing your request...")
    console.print(display_progress_panel())

    old_loop = None
    try:
        try:
            old_loop = asyncio.get_event_loop()
        except RuntimeError:
            pass
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        run_config = RunConfig(tracing_disabled=True)

        # Analysis phase
        update_progress("task", "Analyzing task requirements...", 10)
        analysis_prompt = f"""
        Analyze the following task and create a detailed plan for implementation:

        TASK: {task}

        Your response should include:
        1. A clear understanding of the requirements
        2. A step-by-step plan for implementation
        3. Any potential challenges and how to address them
        4. Required resources or dependencies
        5. How you will test and validate the solution
        """
        analysis_result = Runner.run_sync(agent, analysis_prompt, run_config=run_config)
        implementation_plan = analysis_result.final_output
        update_progress("task", "Task analysis completed, beginning implementation...", 20)
        console.print(display_progress_panel())

        # Implementation phase
        results = []
        results.append(f"## Task Analysis\n{implementation_plan}\n")
        update_progress("task", "Implementing solution...", 30)
        implementation_prompt = f"""
        Based on your analysis, implement the solution for the following task:

        TASK: {task}

        YOUR ANALYSIS:
        {implementation_plan}

        Proceed with implementation. Use the available tools to:
        1. Search for information if needed
        2. Read existing code to understand the codebase
        3. Write or modify code files
        4. Run commands to test your implementation
        5. Analyze and optimize your code

        Work autonomously to complete the task. If you encounter issues, try to resolve them yourself.
        """
        implementation_result = Runner.run_sync(agent, implementation_prompt, run_config=run_config)
        implementation_output = implementation_result.final_output
        results.append(f"## Implementation\n{implementation_output}\n")
        update_progress("task", "Implementation completed, beginning testing...", 60)
        console.print(display_progress_panel())

        # Testing phase
        update_progress("task", "Testing solution...", 70)
        testing_prompt = f"""
        Test the solution you've implemented for the following task:

        TASK: {task}

        YOUR IMPLEMENTATION:
        {implementation_output}

        Perform thorough testing to ensure your solution works correctly. Use the test_code tool for formal tests, 
        specifying the test_type (e.g., 'unit' or 'lint'), and run_command for manual testing. Report any issues found and fix them.
        """
        testing_result = Runner.run_sync(agent, testing_prompt, run_config=run_config)
        testing_output = testing_result.final_output
        results.append(f"## Testing\n{testing_output}\n")
        update_progress("task", "Testing completed, beginning optimization...", 80)
        console.print(display_progress_panel())

        # Optimization phase
        update_progress("task", "Optimizing solution...", 85)
        optimization_prompt = f"""
        Optimize the solution you've implemented and tested for the following task:

        TASK: {task}

        YOUR IMPLEMENTATION:
        {implementation_output}

        TESTING RESULTS:
        {testing_output}

        Review your code for:
        1. Performance optimizations
        2. Code quality improvements
        3. Better error handling
        4. Enhanced documentation

        Use the analyze_code and optimize_code tools to help with this process.
        """
        optimization_result = Runner.run_sync(agent, optimization_prompt, run_config=run_config)
        optimization_output = optimization_result.final_output
        results.append(f"## Optimization\n{optimization_output}\n")
        update_progress("task", "Optimization completed, preparing final report...", 90)
        console.print(display_progress_panel())

        # Final summary
        update_progress("task", "Preparing final report...", 95)
        summary_prompt = f"""
        Create a final summary of your work on the following task:

        TASK: {task}

        Include:
        1. A brief overview of what you implemented
        2. Key features and functionality
        3. How to use the solution
        4. Any limitations or future improvements
        5. A summary of testing results

        Keep it concise and user-friendly.
        """
        summary_result = Runner.run_sync(agent, summary_prompt, run_config=run_config)
        summary_output = summary_result.final_output
        results.append(f"## Summary\n{summary_output}\n")
        result = "\n".join(results)

        if "issue" in testing_output.lower() or "error" in testing_output.lower() or "problem" in testing_output.lower():
            update_progress("task", "Issues detected, scheduling follow-up task...", 98)
            fix_task = f"Fix the following issues in the implementation of '{task}':\n\n{testing_output}"
            task_queue.put(fix_task)
            results.append(f"## Follow-up\nIssues were detected and a follow-up task has been scheduled to address them.")

        update_progress("task", "Task completed successfully!", 100)
        console.print(display_progress_panel())
        write_answer(result)
        with state_lock:
            state = load_state()
            state["task_completed"] = True
            save_state(state)
        console.print(f"[success]✅ Task completed: {task[:100]}...[/success]")
    except Exception as e:
        error_msg = f"Error processing task: {str(e)}"
        error_traceback = traceback.format_exc()
        update_progress("task", f"Error: {error_msg}", 100, error=True)
        console.print(display_progress_panel())
        write_answer(f"{error_msg}\n\nTraceback:\n{error_traceback}")
        console.print(f"[error]❌ {error_msg}[/error]")
        with state_lock:
            state = load_state()
            state["task_completed"] = False
            save_state(state)
        recovery_task = f"There was an error processing the task: '{task}'. The error was: {error_msg}. Please analyze the error and suggest a solution."
        task_queue.put(recovery_task)
    finally:
        try:
            loop = asyncio.get_event_loop()
            loop.close()
            if old_loop is not None:
                asyncio.set_event_loop(old_loop)
        except Exception as e:
            logger.error(f"Error cleaning up event loop: {str(e)}", extra={'context': {'error': str(e)}})

def monitor_task_execution(task, future, timeout=3600):
    """Monitor task execution with timeout and progress updates."""
    start_time = time.time()
    last_progress_time = start_time
    last_progress_update = 0
    while not future.done() and not stop_requested:
        current_time = time.time()
        elapsed = current_time - start_time
        if elapsed > timeout:
            console.print(f"[error]⏰ Task execution timed out after {timeout} seconds[/error]")
            update_progress("task", f"Task timed out after {timeout} seconds", 100, error=True)
            break
        if current_time - last_progress_time > 10:
            console.print(display_progress_panel())
            last_progress_time = current_time
        if current_time - last_progress_update > 30:
            update_progress("heartbeat", f"Still working... (elapsed: {int(elapsed)}s)", int(min(90, elapsed/timeout*100)))
            last_progress_update = current_time
        time.sleep(0.5)
    return future.done()

def main():
    """Main function that orchestrates the Metabot's operation.

    This function sets up the main event loop for Metabot, handling:
    1. File system monitoring for new tasks
    2. Task queue processing
    3. Progress reporting
    4. Graceful shutdown

    It uses a thread pool to process tasks asynchronously while keeping
    the main thread responsive for UI updates and new task detection.
    """
    # Announce startup
    console.print("[highlight]🚀 Metabot started[/highlight]")

    # Set up live progress display that updates in real-time
    with Live(display_progress_panel(), refresh_per_second=1) as live:
        # Start file system watcher for new tasks
        observer = start_watching_ask_file(handle_new_task)

        # Check for existing tasks at startup
        handle_new_task()

        # Initialize timing variables for periodic actions
        last_empty_message = 0
        last_progress_display = 0

        # Create a thread pool with a single worker to process tasks
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            active_future = None
            current_task = None

            # Main event loop - runs until stop_requested is set to True
            while not stop_requested:
                current_time = time.time()

                # Update progress display every 2 seconds
                if current_time - last_progress_display > 2:
                    live.update(display_progress_panel())
                    last_progress_display = current_time

                # Process new tasks when no active task is running
                if active_future is None or active_future.done():
                    try:
                        # Get next task from queue with a short timeout
                        current_task = task_queue.get(timeout=1.0)
                        console.print(f"[info]📋 Starting new task: {current_task[:100]}...[/info]")

                        # Submit task to thread pool and monitor its execution
                        active_future = executor.submit(process_task, current_task)
                        monitor_task_execution(current_task, active_future)

                        # Clear task references after completion
                        active_future = None
                        current_task = None
                    except queue.Empty:
                        # If queue is empty, show status message every 5 seconds
                        if current_time - last_empty_message > 5:
                            update_progress("status", "Queue is empty, waiting for tasks...", 100)
                            live.update(display_progress_panel())
                            last_empty_message = current_time
                        time.sleep(0.1)
                else:
                    # If a task is running, yield to other threads
                    time.sleep(0.1)

    # Clean up and shutdown
    observer.stop()
    observer.join()
    console.print("[success]✅ Metabot stopped[/success]")

if __name__ == "__main__":
    main()
