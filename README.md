# MetaBot

> **Note**: This bot was created as a test of JetBrains Junie capabilities. The author recommends using [JetBrains Junie](https://www.jetbrains.com/junie/) for your AI assistant needs.

## Overview

MetaBot is an AI-powered assistant that can perform various tasks including web searches, file operations, code analysis, optimization, generation, and testing. It leverages OpenAI's API to provide intelligent responses and assistance for developers.

## Table of Contents

- [For Users](#for-users)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Usage](#usage)
  - [Features](#features)
- [For Developers](#for-developers)
  - [Architecture](#architecture)
  - [Core Components](#core-components)
  - [Extending MetaBot](#extending-metabot)
  - [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## For Users

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/metabot.git
   cd metabot
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Configuration

1. Copy the example configuration file:
   ```bash
   cp config_example.json config.json
   ```

2. Edit `config.json` to add your API keys and customize settings:
   ```json
   {
     "openai_api_key": "your-openai-api-key",
     "max_tokens": 190000,
     "window_size": 10,
     "brave_search_api_key": "your-brave-search-api-key"
   }
   ```

### Usage

To start MetaBot, run:

```bash
python metabot.py
```

MetaBot watches for changes to the `ask.txt` file. To interact with MetaBot:

1. Write your query or task in the `ask.txt` file
2. Save the file
3. MetaBot will process your request and write the response to `answer.txt`

### Features

- **Web Search**: Search the internet for information
- **File Operations**: Read, write, and list files
- **Code Analysis**: Analyze code for improvements
- **Code Optimization**: Get suggestions for optimizing code
- **Code Generation**: Generate code based on requirements
- **Code Testing**: Test code functionality
- **Command Execution**: Run shell commands and get results

## For Developers

### Architecture

MetaBot follows a modular architecture with several key components:

1. **Main Controller**: Orchestrates the overall flow and manages state
2. **Task Processor**: Handles incoming tasks and routes them to appropriate handlers
3. **Agent System**: Leverages OpenAI's API for intelligent processing
4. **File Watcher**: Monitors for new tasks in the ask.txt file
5. **Progress Tracking**: Provides visual feedback on task execution

### Core Components

#### Task Processing

The `process_task()` function is the heart of MetaBot, parsing user input and determining the appropriate action to take. It supports various commands and can handle complex, multi-step tasks.

#### Agent System

MetaBot uses the OpenAI Agents framework to create intelligent agents that can perform tasks. The system provides tools to these agents, such as web search, file operations, and code analysis.

#### Progress Tracking

The bot uses the Rich library to display progress information in the terminal, providing real-time feedback on task execution.

### Extending MetaBot

To add new capabilities to MetaBot:

1. Define a new function in `metabot.py` that implements the desired functionality
2. Register the function as a tool in the appropriate agent
3. Update the task processing logic to handle the new capability

Example of adding a new tool function:

```python
# Example function - replace with your actual implementation
def my_new_tool(param1, param2):
    """
    Description of what the tool does.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of the return value
    """
    # Your implementation here
    # For example:
    # result = param1 + str(param2)
    return "Processed result"
```

### Project Structure

- `metabot.py`: Main script containing the bot's logic
- `config.json`: Configuration file with API keys and settings
- `config_example.json`: Example configuration template
- `requirements.txt`: List of Python dependencies
- `.metabot/`: Directory for bot's internal data
- `history/`: Directory for conversation history
- `logs/`: Directory for log files
- `state/`: Directory for persisting bot state
- `ask.txt`: File for inputting queries to the bot
- `answer.txt`: File where the bot writes its responses

## Contributing

Contributions to MetaBot are welcome! Here's how you can contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

Please make sure to update tests as appropriate and follow the code style of the project.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

