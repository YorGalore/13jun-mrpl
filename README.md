# SEPSES Cybersecurity Knowledge Graph Chatbot

SEPSES Cybersecurity Knowledge Graph Chatbot is an LLM-based cybersecurity analysis assistant that integrates Large Language Models (LLMs) with the SEPSES Cybersecurity Knowledge Graph (CSKG) to provide explainable and context-aware cybersecurity analysis.

Unlike general-purpose AI chatbots that rely only on pretrained language knowledge, this system utilizes structured cybersecurity knowledge from SEPSES CSKG combined with Retrieval-Augmented Generation (RAG) / GraphRAG mechanisms to reduce hallucination and improve analytical accuracy.

The chatbot supports cybersecurity question-answering, threat actor analysis, malware investigation, vulnerability relationship analysis, and security log analysis.

## Team Members
- Diayu Nur Aini          24/537751/PA/22792 - Diayu Nur Aini
- Freta Yordinia Laura    24/533444/PA/22576 - Yor
- Herlina Iin Nur Soleha  24/541333/PA/22962 - Herlina-Iin
- Ananda Auliya Rahma     24/533691/PA/22608 - anandauliya

## Project Objectives
- Integrate SEPSES CSKG with LLMs for cybersecurity analysis
- Implement GraphRAG / RAG architecture
- Support explainable cybersecurity question-answering
- Analyze relationships between vulnerabilities, malware, threat actors, and attacks
- Evaluate multiple LLMs for cybersecurity tasks
- Provide an interactive chatbot interface for analysts and researchers

## Features

### Cybersecurity Question Answering
- Ask cybersecurity-related questions using natural language
- Retrieve structured information from SEPSES CSKG
- Generate explainable responses with graph context

### Threat Actor Analysis
- Analyze threat actors and associated attack patterns
- Discover related malware, vulnerabilities, and campaigns

### Malware Investigation
- Investigate malware families and their behaviors
- Explore malware relationships within the knowledge graph

### Vulnerability Relationship Analysis
- Analyze CVE relationships
- Discover affected systems, attack vectors, and linked malware

### Security Log Analysis
- Upload and analyze local security logs
- Combine vector database retrieval with LLM reasoning

### RAG / GraphRAG Integration
- Knowledge retrieval from RDF/SPARQL resources
- Context-aware answer generation using LLMs

## Documentation Details

### System Overview
The system consists of the following components:

- **Frontend Interface**: User chatbot interface 
- **Backend Service**: Handles query processing and LLM orchestration 
- **Knowledge Retrieval Layer**:
  - SPARQL queries to SEPSES CSKG
  - RDF/Turtle graph traversal
  - Vector database retrieval 
- **LLM Layer**:
  - Multiple LLMs
  - Used for response generation and reasoning
- **RAG / GraphRAG Pipeline**:
  - Combines retrieved graph data + semantic search results
  - Feeds structured context into LLM for final response

## Dataset & Knowledge Source
Primary dataset:
- SEPSES Cybersecurity Knowledge Graph (CSKG)

GitHub:
https://github.com/sepses/cyber-kg-converter

Research References:
- https://link.springer.com/chapter/10.1007/978-3-030-30796-7_13
- https://eprints.cs.univie.ac.at/8177/1/ISWC24_ICS-SEC__Andreas%20Ekelhart.pdf
- https://ceur-ws.org/Vol-4079/paper11.pdf

## Vocabularies
Several vocabularies are developed to represent the SEPSES-CSKG knowledge graphs, as follows:

| Prefix | Description                               | Link                                                                                   |
|--------|-------------------------------------------|----------------------------------------------------------------------------------------|
| capec  | Common Attack Pattern Enumeration and Classification (CAPEC) | <a href="http://w3id.org/sepses/vocab/ref/capec" target="_blank">http://w3id.org/sepses/vocab/ref/capec</a>     |
| cwe    | Common Weakness Enumeration (CWE)         | <a href="http://w3id.org/sepses/vocab/ref/cwe" target="_blank">http://w3id.org/sepses/vocab/ref/cwe</a>         |
| cve    | Common Vulnerabilities and Exposures (CVE) | <a href="http://w3id.org/sepses/vocab/ref/cve" target="_blank">http://w3id.org/sepses/vocab/ref/cve</a>         |
| cvss   | Common Vulnerability Scoring System (CVSS)| <a href="http://w3id.org/sepses/vocab/ref/cvss" target="_blank">http://w3id.org/sepses/vocab/ref/cvss</a>       |
| cpe    | Common Platform Enumeration (CPE)         | <a href="http://w3id.org/sepses/vocab/ref/cpe" target="_blank">http://w3id.org/sepses/vocab/ref/cpe</a>         |




## Access Services

Example queries are now added (`example-queries.txt`), which can be tested in our [SPARQL endpoint](https://w3id.org/sepses/sparql).

Other interface beyond SPARQL are also provided, such as [Linked Data Interface](https://sepses.ifs.tuwien.ac.at/resource/cve/CVE-2018-4449) (example),  [Triple Pattern Fragment](http://ldf-server.sepses.ifs.tuwien.ac.at/) and [Dump-files](https://sepses.ifs.tuwien.ac.at/index.php/datasets/)   (in .turtle and .HDT).

## License

The ECS-SEC KG Engine is written by SEPSES team and released under the [MIT license](http://opensource.org/licenses/MIT).
