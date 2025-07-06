# DefectDojo Custom Parsers

[![DefectDojo](https://img.shields.io/badge/DefectDojo-Compatible-brightgreen.svg)](https://github.com/DefectDojo/django-DefectDojo)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)

A collection of custom parsers for [DefectDojo](https://github.com/DefectDojo/django-DefectDojo), the leading open-source vulnerability management platform. These parsers extend DefectDojo's scanning capabilities with enhanced support for popular security tools.

## 🚀 Features

### 📊 Enhanced Parsers

- **Netsparker Parser** (`netsparker/parser.py`)
  - Full JSON format support
  - Advanced vulnerability classification
  - CVSS scoring integration
  - False positive detection
  - Risk acceptance handling
  - Comprehensive request/response capture

- **Tenable Parser** (`tenable/xml_format.py`)
  - Enhanced XML format parsing
  - Improved severity mapping
  - Better CVE/CWE extraction
  - Advanced deduplication logic
  - Comprehensive field mapping

### 🔧 Key Improvements

- **Better Data Extraction**: Enhanced parsing of vulnerability details, CVSS scores, and metadata
- **Improved Deduplication**: More accurate duplicate detection algorithms
- **Enhanced Severity Mapping**: Better conversion between scanner and DefectDojo severity levels
- **Comprehensive Logging**: Detailed logging for troubleshooting and debugging
- **Docker Integration**: Ready-to-use Docker Compose configuration

## 📋 Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)
- [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) (latest version recommended)
- Python 3.8+ (for development)

## 🛠️ Installation

### Quick Start with Docker

1. **Clone this repository:**
   ```bash
   git clone <your-repo-url>
   cd defectdojo
   ```

2. **Start DefectDojo with custom parsers:**
   ```bash
   docker compose up -d
   ```

3. **Get admin credentials:**
   ```bash
   docker compose logs initializer | grep "Admin password:"
   ```

4. **Access DefectDojo:**
   - Open your browser and navigate to `http://localhost:8080`
   - Login with the admin credentials from step 3

### Manual Installation

1. **Copy parser files to your DefectDojo installation:**
   ```bash
   # For Netsparker parser
   cp netsparker/parser.py /path/to/defectdojo/dojo/tools/netsparker/
   
   # For Tenable parser
   cp tenable/xml_format.py /path/to/defectdojo/dojo/tools/tenable/
   ```

2. **Restart your DefectDojo instance**

## 📖 Usage

### Netsparker Integration

1. **Export scan results from Netsparker in JSON format**
2. **Upload to DefectDojo:**
   - Navigate to your product/engagement
   - Click "Add Finding" → "Import Scan Results"
   - Select "Netsparker Scan" as the scan type
   - Upload your JSON report

### Tenable Integration

1. **Export scan results from Tenable/Nessus in XML format (NessusClientData_v2)**
2. **Upload to DefectDojo:**
   - Navigate to your product/engagement
   - Click "Add Finding" → "Import Scan Results"
   - Select "Tenable Scan" as the scan type
   - Upload your XML report

## 🔧 Configuration

### Docker Environment Variables

The `docker-compose.yaml` file includes volume mounts for the custom parsers:

```yaml
volumes:
  - ./tenable/xml_format.py:/app/dojo/tools/tenable/xml_format.py
  - ./netsparker/parser.py:/app/dojo/tools/netsparker/parser.py
```

### Custom Settings

You can customize the parsers by modifying the source files:

- **Netsparker Parser**: Edit `netsparker/parser.py` for JSON format adjustments
- **Tenable Parser**: Edit `tenable/xml_format.py` for XML format enhancements

## 🧪 Testing

### Test Your Parsers

1. **Generate test reports** from your security tools
2. **Upload to DefectDojo** using the custom parsers
3. **Verify findings** are imported correctly with proper:
   - Severity levels
   - CVSS scores
   - CVE/CWE mappings
   - Descriptions and mitigations

### Sample Test Data

For testing purposes, you can use sample reports from:
- Netsparker: Export a test scan in JSON format
- Tenable: Export a test scan in XML format (NessusClientData_v2)

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Development Setup

1. **Fork the repository**
2. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Test thoroughly**
5. **Submit a pull request**

### Code Style

- Follow Python PEP 8 guidelines
- Add comprehensive docstrings
- Include type hints where appropriate
- Write unit tests for new features

### Reporting Issues

When reporting issues, please include:
- DefectDojo version
- Parser type (Netsparker/Tenable)
- Sample scan data (anonymized)
- Expected vs actual behavior
- Error messages/logs

## 📚 Documentation

### Parser Specifications

#### Netsparker Parser
- **Input Format**: JSON
- **Supported Fields**: Title, Description, Severity, CVSS, CWE, References
- **Special Features**: False positive detection, risk acceptance

#### Tenable Parser
- **Input Format**: XML (NessusClientData_v2)
- **Supported Fields**: Title, Description, Severity, CVSS, CVE, CWE
- **Special Features**: Enhanced deduplication, improved severity mapping

### API Reference

For detailed API documentation, refer to the [DefectDojo documentation](https://defectdojo.github.io/django-DefectDojo/).

## 🔗 Related Links

- [DefectDojo Main Repository](https://github.com/DefectDojo/django-DefectDojo)
- [DefectDojo Documentation](https://defectdojo.github.io/django-DefectDojo/)
- [DefectDojo Community](https://owasp.org/www-project-defectdojo/)
- [Netsparker Documentation](https://www.netsparker.com/support/)
- [Tenable Documentation](https://docs.tenable.com/)

## 📄 License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [DefectDojo Community](https://github.com/DefectDojo/django-DefectDojo) for the excellent vulnerability management platform
- [OWASP](https://owasp.org/) for supporting the DefectDojo project
- All contributors who have helped improve these parsers

---

**Note**: These parsers are designed to work with the latest version of DefectDojo. For compatibility with older versions, please check the DefectDojo release notes and adjust the parser code accordingly. 