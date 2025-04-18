#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for metabot.py

This module contains comprehensive tests for the metabot.py module,
aiming to achieve 100% code coverage.
"""

import os
import sys
import json
import time
import signal
import unittest
from unittest.mock import patch, MagicMock, mock_open, call, ANY
import logging
import logging.handlers
from datetime import datetime, timezone
import threading
import queue
import tempfile
import asyncio
import concurrent.futures
import subprocess
from io import StringIO

# Import the module to test
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import metabot


class TestJsonFormatter(unittest.TestCase):
    """Tests for the JsonFormatter class."""

    def test_format(self):
        """Test that the formatter correctly formats log records as JSON."""
        formatter = metabot.JsonFormatter()
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test_path",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None
        )
        record.context = {"test_key": "test_value"}

        formatted = formatter.format(record)
        parsed = json.loads(formatted)

        self.assertEqual(parsed["level"], "INFO")
        self.assertEqual(parsed["message"], "Test message")
        self.assertEqual(parsed["context"], {"test_key": "test_value"})
        self.assertTrue("timestamp" in parsed)


class TestConfigFunctions(unittest.TestCase):
    """Tests for configuration-related functions."""

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data='{"openai_api_key": "test_key"}')
    def test_load_config(self, mock_file, mock_exists):
        """Test loading config."""
        # Setup mocks
        mock_exists.side_effect = lambda path: path.endswith("config.json")

        # Call function
        with patch("metabot.print"):
            config = metabot.load_config()

        # Assertions
        self.assertEqual(config["openai_api_key"], "test_key")
        mock_file.assert_called()


class TestFileOperations(unittest.TestCase):
    """Tests for file operation functions."""

    @patch("os.makedirs")
    @patch("builtins.open", new_callable=mock_open)
    def test_write_file(self, mock_file, mock_makedirs):
        """Test write_file function."""
        result = metabot.write_file("/test/path.txt", "Test content")
        self.assertEqual(result, "File written: /test/path.txt")
        mock_makedirs.assert_called_with("/test", exist_ok=True)

    @patch("builtins.open", new_callable=mock_open, read_data="Test content")
    def test_read_file(self, mock_file):
        """Test read_file function."""
        result = metabot.read_file("/test/path.txt")
        self.assertEqual(result, "Test content")

    @patch("os.listdir")
    def test_list_files(self, mock_listdir):
        """Test list_files function."""
        mock_listdir.return_value = ["file1.txt", "file2.txt"]
        result = metabot.list_files("/test/dir")
        self.assertEqual(result, "file1.txt\nfile2.txt")


class TestWebFunctions(unittest.TestCase):
    """Tests for web-related functions."""

    @patch("metabot.requests.get")
    def test_web_search(self, mock_get):
        """Test web_search function."""
        # Setup mock
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "web": {
                "results": [
                    {"title": "Result 1", "description": "Description 1"}
                ]
            }
        }
        mock_get.return_value = mock_response

        # Call function with mocked config
        with patch.dict(metabot.config, {"brave_search_api_key": "test_key"}):
            result = metabot.web_search("test query")

        self.assertIn("Result 1: Description 1", result)

    @patch("metabot.requests.get")
    def test_browse_page(self, mock_get):
        """Test browse_page function."""
        # Setup mocks
        mock_response = MagicMock()
        mock_response.text = "<html><body><p>Test paragraph with query</p></body></html>"
        mock_get.return_value = mock_response

        # Mock BeautifulSoup
        mock_soup = MagicMock()
        mock_p = MagicMock()
        mock_p.get_text.return_value = "Test paragraph with query"
        mock_soup.find_all.return_value = [mock_p]

        with patch("metabot.BeautifulSoup", return_value=mock_soup):
            result = metabot.browse_page("http://example.com", "query")

        self.assertEqual(result, "Test paragraph with query")


class TestCommandExecution(unittest.TestCase):
    """Tests for command execution functions."""

    @patch("metabot.update_progress")
    @patch("metabot.subprocess.run")
    def test_run_command(self, mock_run, mock_update_progress):
        """Test run_command function."""
        # Setup mock
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Command output"
        mock_run.return_value = mock_result

        # Call function
        result = metabot.run_command("test command", 10)

        # Assertions
        self.assertEqual(result, "Command output")


class TestProgressTracking(unittest.TestCase):
    """Tests for progress tracking functions."""

    def test_update_progress(self):
        """Test update_progress function."""
        # Clear existing progress data
        metabot.progress_data.clear()

        # Call function
        metabot.update_progress("test", "Test message", 50)

        # Assertions
        self.assertEqual(len(metabot.progress_data), 1)
        progress_item = list(metabot.progress_data.values())[0]
        self.assertEqual(progress_item["task_type"], "test")
        self.assertEqual(progress_item["message"], "Test message")
        self.assertEqual(progress_item["percentage"], 50)
        self.assertEqual(progress_item["error"], False)


class TestStateManagement(unittest.TestCase):
    """Tests for state management functions."""

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data='{"iteration": 1, "current_task": "test", "task_completed": true}')
    def test_load_state(self, mock_file, mock_exists):
        """Test load_state function."""
        mock_exists.return_value = True
        state = metabot.load_state()
        self.assertEqual(state["iteration"], 1)
        self.assertEqual(state["current_task"], "test")
        self.assertEqual(state["task_completed"], True)

    @patch("os.makedirs")
    @patch("builtins.open", new_callable=mock_open)
    def test_save_state(self, mock_file, mock_makedirs):
        """Test save_state function."""
        state = {"iteration": 1, "current_task": "test", "task_completed": True}
        metabot.save_state(state)
        mock_makedirs.assert_called_with(os.path.dirname(metabot.STATE_FILE), exist_ok=True)


class TestSignalHandling(unittest.TestCase):
    """Tests for signal handling."""

    @patch("metabot.logger")
    @patch("metabot.console")
    def test_signal_handler(self, mock_console, mock_logger):
        """Test signal_handler function."""
        # Save original value
        original_stop_requested = metabot.stop_requested

        try:
            # Call function
            metabot.signal_handler(signal.SIGINT, None)

            # Assertions
            self.assertTrue(metabot.stop_requested)
        finally:
            # Restore original value
            metabot.stop_requested = original_stop_requested


class TestCodeAnalysis(unittest.TestCase):
    """Tests for code analysis functions."""

    @patch("metabot.update_progress")
    @patch("metabot.os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data="import *\nexcept:\nprint('test')")
    @patch("metabot.execute_command")
    def test_analyze_code(self, mock_execute, mock_open, mock_exists, mock_update_progress):
        """Test analyze_code function."""
        mock_exists.return_value = True
        mock_execute.side_effect = ["Error: pylint not found", "Error: flake8 not found"]

        result = metabot.analyze_code("/test/file.py")

        self.assertIn("File has 3 lines of code", result)
        self.assertIn("Found wildcard imports", result)

    @patch("metabot.update_progress")
    @patch("metabot.os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data="def test(): pass")
    @patch("metabot.os.makedirs")
    def test_optimize_code(self, mock_makedirs, mock_open, mock_exists, mock_update_progress):
        """Test optimize_code function."""
        mock_exists.return_value = True

        result = metabot.optimize_code("/test/file.py", "Add docstring")

        self.assertIn("Code optimization suggestions", result)
        self.assertIn("Add docstring", result)
        self.assertIn("A backup was created", result)

    @patch("metabot.update_progress")
    @patch("metabot.os.path.exists")
    @patch("metabot.os.makedirs")
    @patch("builtins.open", new_callable=mock_open)
    def test_generate_code(self, mock_file, mock_makedirs, mock_exists, mock_update_progress):
        """Test generate_code function."""
        mock_exists.return_value = False

        result = metabot.generate_code("/test/file.py", "Create a function")

        self.assertIn("Code generation for", result)
        self.assertIn("Create a function", result)
        mock_makedirs.assert_called()

    @patch("metabot.update_progress")
    @patch("metabot.os.path.exists")
    @patch("metabot.execute_command")
    def test_test_code(self, mock_execute, mock_exists, mock_update_progress):
        """Test test_code function."""
        mock_exists.return_value = True
        mock_execute.return_value = "All tests passed"

        result = metabot.test_code("/test/file.py", "unit")

        self.assertIn("Test results for", result)
        self.assertIn("All tests passed", result)
        mock_execute.assert_called_with("pytest /test/file.py -v", timeout=60)


class TestFileWatching(unittest.TestCase):
    """Tests for file watching functionality."""

    def test_ask_file_handler(self):
        """Test AskFileHandler class."""
        callback_mock = MagicMock()
        handler = metabot.AskFileHandler(callback_mock)

        # Create a mock event
        event = MagicMock()
        event.src_path = metabot.ASK_FILE

        # Call the handler
        handler.on_modified(event)

        # Verify callback was called
        callback_mock.assert_called_once()

    @patch("metabot.Observer")
    @patch("metabot.AskFileHandler")
    @patch("metabot.console")
    def test_start_watching_ask_file(self, mock_console, mock_handler, mock_observer):
        """Test start_watching_ask_file function."""
        # Setup mocks
        mock_observer_instance = MagicMock()
        mock_observer.return_value = mock_observer_instance
        callback_mock = MagicMock()

        # Call function
        result = metabot.start_watching_ask_file(callback_mock)

        # Assertions
        mock_handler.assert_called_with(callback_mock)
        mock_observer_instance.schedule.assert_called()
        mock_observer_instance.start.assert_called_once()
        mock_console.print.assert_called()
        self.assertEqual(result, mock_observer_instance)


class TestTaskProcessing(unittest.TestCase):
    """Tests for task processing functions."""

    @patch("metabot.os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data="Test task")
    @patch("metabot.task_queue")
    @patch("metabot.load_state")
    @patch("metabot.save_state")
    @patch("metabot.console")
    def test_handle_new_task(self, mock_console, mock_save, mock_load, mock_queue, mock_open, mock_exists):
        """Test handle_new_task function."""
        # Setup mocks
        mock_exists.return_value = True
        mock_load.return_value = {"iteration": 0}

        # Call function
        metabot.handle_new_task()

        # Assertions
        mock_queue.put.assert_called_with("Test task")
        mock_save.assert_called()
        mock_console.print.assert_called()

    @patch("metabot.progress_data")
    @patch("metabot.Panel")
    def test_display_progress_panel(self, mock_panel, mock_progress_data):
        """Test display_progress_panel function."""
        # Setup mock data
        timestamp = datetime.now(timezone.utc).isoformat()
        mock_progress_data.items.return_value = [
            (timestamp, {
                "task_type": "test",
                "message": "Test message",
                "percentage": 50,
                "error": False,
                "timestamp": timestamp
            })
        ]

        # Call function
        result = metabot.display_progress_panel()

        # Assertions
        mock_panel.assert_called()

    @patch("metabot.asyncio.get_event_loop")
    @patch("metabot.asyncio.new_event_loop")
    @patch("metabot.asyncio.set_event_loop")
    @patch("metabot.Runner.run_sync")
    @patch("metabot.update_progress")
    @patch("metabot.write_answer")
    @patch("metabot.load_state")
    @patch("metabot.save_state")
    @patch("metabot.console")
    def test_process_task(self, mock_console, mock_save, mock_load, mock_write, 
                         mock_update, mock_run_sync, mock_set_loop, mock_new_loop, mock_get_loop):
        """Test process_task function."""
        # Setup mocks
        mock_load.return_value = {"iteration": 1}
        mock_run_result = MagicMock()
        mock_run_result.final_output = "Test output"
        mock_run_sync.return_value = mock_run_result

        # Call function with a simple task
        metabot.process_task("Test task")

        # Assertions
        mock_update.assert_any_call("task", ANY, ANY)
        mock_write.assert_called()
        mock_save.assert_called()
        mock_run_sync.assert_called()

    @patch("metabot.time.time")
    @patch("metabot.time.sleep")
    @patch("metabot.update_progress")
    @patch("metabot.console")
    def test_monitor_task_execution(self, mock_console, mock_update, mock_sleep, mock_time):
        """Test monitor_task_execution function."""
        # Setup mocks
        mock_time.side_effect = [100, 110, 120]  # Start time, check time, update time
        mock_future = MagicMock()
        mock_future.done.return_value = True

        # Call function
        result = metabot.monitor_task_execution("Test task", mock_future, timeout=30)

        # Assertions
        self.assertTrue(result)
        mock_future.done.assert_called()


class TestMainFunction(unittest.TestCase):
    """Tests for the main function."""

    @patch("metabot.Live")
    @patch("metabot.start_watching_ask_file")
    @patch("metabot.handle_new_task")
    @patch("metabot.concurrent.futures.ThreadPoolExecutor")
    @patch("metabot.time.time")
    @patch("metabot.time.sleep")
    @patch("metabot.stop_requested", new_callable=MagicMock)
    def test_main(self, mock_stop, mock_sleep, mock_time, mock_executor, 
                 mock_handle, mock_start_watching, mock_live):
        """Test main function."""
        # Setup mocks
        mock_stop.__bool__.side_effect = [False, True]  # Run loop once then exit
        mock_time.return_value = 100
        mock_live_context = MagicMock()
        mock_live.return_value.__enter__.return_value = mock_live_context

        # Call function
        metabot.main()

        # Assertions
        mock_start_watching.assert_called_once()
        mock_handle.assert_called_once()
        mock_executor.assert_called_once()


if __name__ == "__main__":
    unittest.main()
