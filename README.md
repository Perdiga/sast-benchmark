[![CodeQL](https://github.com/Perdiga/sast-benchmark/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Perdiga/sast-benchmark/actions/workflows/github-code-scanning/codeql)

# SAST Benchmark

**SAST Benchmark** is an open-source platform designed to compare and evaluate the effectiveness of various Static Application Security Testing (SAST) tools available in the industry. It includes support for free-to-use tools across multiple programming languages and frameworks, making it a versatile choice for security assessments.

---

## Runners

Runners are located in the `domain/use_case` folder. Each runner is responsible for executing a specific SAST tool. To add a new tool:

1. Create a new file implementing the `SastRunner` interface.
2. Update the `config.json` file to include your new runner.

### Available Runners

| Runner    | Supported Languages | Website |
|-----------|---------------------|---------|
|CodeQL     | C/C++, C#, Go, Java, Kotlin, JavaScript, Python, Ruby, Swift, TypeScript| [CodeQL Overview](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/)
|SonarQube  |ABAP, C#, C/C++, CloudFormation, COBOL, CSS, Docker, Flex, Go, HMTL, Java, JavaScript, Kotlin, Kubernetes/Helm, Objective-C, PHP, PLI, PLSQL, Python, Ruby, Scala, Secrets, Swift, Terraform, TSQL, TypeScript, VB.NET, XML|[SonarQube Overview](https://docs.sonarsource.com/sonarqube/10.5/analyzing-source-code/languages/overview/)
|Trivy      |.Net, C/C++, Dart, Elixir, Go, Java, JavaScript, PHP, Python, Ruby, Rust, Swift| [Trivy Overview](https://aquasecurity.github.io/trivy/v0.47/docs/coverage/language/)
|Horusec    | C/C++, C#, Dart, Elixit, Go, HMTL, Java, JavaScript, JSON, Kotlin, Kubernetes, Leeks, Nginx, PHP, Python, Ruby, Swift, Teraform, TypeScript | [Horusec Overview](https://docs.horusec.io/docs/cli/analysis-tools/overview/)

---

## Results

Scan results from each tool are saved in the `scan_results` folder for easy access and analysis.

---

## Configuration

The application configuration is managed via the `config.json` file. Below are the configurable options:

- **`application.filter_languages`**: An array specifying which languages from the `repos` object should be analyzed.
- **`application.max_workers`**: Defines the maximum number of simultaneous processes the application can execute.
- **`application.runners`**: Defines the runners that will be executed.
- **`repos.vulnerable`**: A dictionary of repositories known to contain vulnerabilities.
- **`repos.non_vulnerable`**: A dictionary of repositories expected to be free of vulnerabilities.

---

## Running the Application

1. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application
    ```bash
   python3 main.py
   ```
