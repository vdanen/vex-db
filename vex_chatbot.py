#!/usr/bin/env python3
"""
VEX Data Chatbot - RAG-based system for querying VEX vulnerability data
Uses local LLM via Ollama and vector embeddings for document retrieval
"""

import os
import sys
import sqlite3
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import json
import logging

# RAG and ML dependencies
import chromadb
from sentence_transformers import SentenceTransformer
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
try:
    from langchain_huggingface import HuggingFaceEmbeddings
except ImportError:
    from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_ollama import OllamaLLM
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate
from langchain.schema import Document

# Database
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VEXDataLoader:
    """Load and prepare VEX data from SQLite database or HuggingFace datasets"""
    
    def __init__(self, db_path: str = "vex.db", use_huggingface: bool = False, hf_repo_id: str = None):
        self.db_path = db_path
        self.use_huggingface = use_huggingface
        self.hf_repo_id = hf_repo_id
        
        if use_huggingface:
            if not hf_repo_id:
                raise ValueError("hf_repo_id must be provided when use_huggingface=True")
            logger.info(f"Using HuggingFace dataset: {hf_repo_id}")
        else:
            if not Path(db_path).exists():
                raise FileNotFoundError(f"Database file '{db_path}' not found!")
            logger.info(f"Using SQLite database: {db_path}")
    
    def load_vex_data(self) -> List[Document]:
        """Load VEX data and convert to langchain Documents"""
        if self.use_huggingface:
            return self._load_from_huggingface()
        else:
            return self._load_from_sqlite()
    
    def _load_from_huggingface(self) -> List[Document]:
        """Load VEX data from HuggingFace datasets"""
        logger.info("Loading VEX data from HuggingFace datasets...")
        
        try:
            from datasets import load_dataset
            
            # Load both CVE and affects datasets
            cve_dataset = load_dataset(f"{self.hf_repo_id}-cve", split="train")
            affects_dataset = load_dataset(f"{self.hf_repo_id}-affects", split="train")
            
            logger.info(f"Loaded {len(cve_dataset):,} CVEs and {len(affects_dataset):,} product records from HuggingFace")
            
            # Create statistics document
            stats_doc = self._create_hf_stats_document(cve_dataset, affects_dataset)
            documents = [stats_doc]
            
            # Convert datasets to pandas for easier processing
            cve_df = cve_dataset.to_pandas()
            affects_df = affects_dataset.to_pandas()
            
            # Group affects by CVE
            affects_grouped = affects_df.groupby('cve').agg({
                'product': lambda x: '; '.join(x.dropna().unique()),
                'state': lambda x: '; '.join(x.dropna().unique()),
                'components': lambda x: '; '.join(x.dropna().unique()),
                'reason': lambda x: '; '.join(x.dropna().unique())
            }).reset_index()
            
            # Merge CVE data with grouped affects
            merged_df = cve_df.merge(affects_grouped, on='cve', how='left')
            
            # Create documents
            for _, row in merged_df.iterrows():
                content_parts = [
                    f"CVE: {row['cve']}",
                    f"Description: {row.get('description', 'N/A')}",
                    f"CVSS Score: {row.get('cvss_score', 'N/A')}",
                    f"Severity: {row.get('severity', 'N/A')}",
                    f"Public Date: {row.get('public_date', 'N/A')}",
                    f"CWE: {row.get('cwe', 'N/A')}",
                    f"Affected Products: {row.get('product', 'N/A')}",
                    f"Vulnerability States: {row.get('state', 'N/A')}",
                    f"Components: {row.get('components', 'N/A')}",
                    f"Reasons: {row.get('reason', 'N/A')}"
                ]
                
                content = "\n".join(content_parts)
                
                metadata = {
                    "cve": str(row['cve']) if row['cve'] else None,
                    "cvss_score": float(row.get('cvss_score')) if row.get('cvss_score') else None,
                    "severity": str(row.get('severity')) if row.get('severity') else None,
                    "public_date": str(row.get('public_date')) if row.get('public_date') else None,
                    "source": "huggingface_dataset"
                }
                
                documents.append(Document(page_content=content, metadata=metadata))
            
            logger.info(f"Created {len(documents)} documents from HuggingFace datasets (including statistics)")
            return documents
            
        except ImportError:
            raise ImportError("datasets package is required for HuggingFace integration. Install with: pip install datasets")
        except Exception as e:
            logger.error(f"Failed to load from HuggingFace: {e}")
            raise
    
    def _create_hf_stats_document(self, cve_dataset, affects_dataset) -> Document:
        """Create statistics document from HuggingFace datasets"""
        
        # Convert to pandas for analysis
        cve_df = cve_dataset.to_pandas()
        affects_df = affects_dataset.to_pandas()
        
        total_cves = len(cve_df)
        total_products = len(affects_df)
        unique_products = affects_df['product'].nunique()
        
        # Calculate statistics
        severity_stats = cve_df['severity'].value_counts()
        
        # Extract year from public_date and count
        cve_df['year'] = pd.to_datetime(cve_df['public_date'], errors='coerce').dt.year
        year_stats = cve_df['year'].value_counts().sort_index(ascending=False).head(10)
        
        state_stats = affects_df['state'].value_counts()
        top_products = affects_df['product'].value_counts().head(10)
        
        stats_content = [
            "VEX DATABASE COMPREHENSIVE STATISTICS AND OVERVIEW",
            "=" * 60,
            "",
            "This document contains complete statistics about the VEX vulnerability database.",
            "Use this information to answer questions about totals, counts, and distributions.",
            "Data source: HuggingFace Datasets",
            "",
            "COMMON QUESTIONS AND ANSWERS:",
            "- How many CVEs are in the database? Answer: See total CVEs below",
            "- What is the total number of vulnerabilities? Answer: See total CVEs below", 
            "- How many vulnerabilities are there? Answer: See total CVEs below",
            "- What is the CVE count? Answer: See total CVEs below",
            "- How many security issues are tracked? Answer: See total CVEs below",
            "- Database size and statistics? Answer: See totals below",
            "",
            f"TOTAL RECORDS IN DATABASE:",
            f"- Total CVEs: {total_cves:,} vulnerabilities",
            f"- Total Product Records: {total_products:,} affected product entries",
            f"- Unique Products: {unique_products:,} distinct products",
            "",
            "CVE SEVERITY DISTRIBUTION:"
        ]
        
        for severity, count in severity_stats.items():
            stats_content.append(f"- {severity}: {count:,} CVEs")
        
        stats_content.extend(["", "CVE DISTRIBUTION BY YEAR (Recent 10 years):"])
        for year, count in year_stats.items():
            if pd.notna(year):
                stats_content.append(f"- {int(year)}: {count:,} CVEs")
        
        stats_content.extend(["", "VULNERABILITY STATES DISTRIBUTION:"])
        for state, count in state_stats.items():
            stats_content.append(f"- {state}: {count:,} product records")
        
        stats_content.extend(["", "TOP 10 MOST AFFECTED PRODUCTS:"])
        for product, count in top_products.items():
            stats_content.append(f"- {str(product)[:50]}: {count:,} vulnerability records")
        
        content = "\n".join(stats_content)
        
        metadata = {
            "cve": "DATABASE_STATISTICS",
            "total_cves": int(total_cves),
            "total_products": int(total_products),
            "source": "huggingface_dataset_stats",
            "document_type": "statistics"
        }
        
        return Document(page_content=content, metadata=metadata)
    
    def _load_from_sqlite(self) -> List[Document]:
        """Load VEX data from SQLite database"""
        logger.info("Loading VEX data from database...")
        
        conn = sqlite3.connect(self.db_path)
        
        # First, create a comprehensive database statistics document
        stats_doc = self._create_database_stats_document(conn)
        documents = [stats_doc]
        
        # Get CVE information with affects data
        query = """
        SELECT 
            c.cve,
            c.description,
            c.cvss_score,
            c.severity,
            c.public_date,
            c.cwe,
            GROUP_CONCAT(DISTINCT a.product) as products,
            GROUP_CONCAT(DISTINCT a.state) as states,
            GROUP_CONCAT(DISTINCT a.components) as components,
            GROUP_CONCAT(DISTINCT a.reason) as reasons
        FROM cve c
        LEFT JOIN affects a ON c.cve = a.cve
        GROUP BY c.cve
        ORDER BY c.cve
        """
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        for _, row in df.iterrows():
            # Handle comma-separated lists and convert to semicolon-separated for better readability
            products = row['products'].replace(',', '; ') if row['products'] else 'N/A'
            states = row['states'].replace(',', '; ') if row['states'] else 'N/A'
            components = row['components'].replace(',', '; ') if row['components'] else 'N/A'
            reasons = row['reasons'].replace(',', '; ') if row['reasons'] else 'N/A'
            
            content_parts = [
                f"CVE: {row['cve']}",
                f"Description: {row['description'] or 'N/A'}",
                f"CVSS Score: {row['cvss_score'] or 'N/A'}",
                f"Severity: {row['severity'] or 'N/A'}",
                f"Public Date: {row['public_date'] or 'N/A'}",
                f"CWE: {row['cwe'] or 'N/A'}",
                f"Affected Products: {products}",
                f"Vulnerability States: {states}",
                f"Components: {components}",
                f"Reasons: {reasons}"
            ]
            
            content = "\n".join(content_parts)
            
            metadata = {
                "cve": str(row['cve']) if row['cve'] else None,
                "cvss_score": float(row['cvss_score']) if row['cvss_score'] else None,
                "severity": str(row['severity']) if row['severity'] else None,
                "public_date": str(row['public_date']) if row['public_date'] else None,
                "source": "vex_database"
            }
            
            documents.append(Document(page_content=content, metadata=metadata))
        
        logger.info(f"Loaded {len(documents)} VEX documents (including database statistics)")
        return documents
    
    def _create_database_stats_document(self, conn) -> Document:
        """Create a comprehensive database statistics document for better RAG retrieval"""
        
        # Get comprehensive statistics
        stats_queries = {
            'total_cves': "SELECT COUNT(*) as count FROM cve",
            'total_products': "SELECT COUNT(*) as count FROM affects",
            'unique_products': "SELECT COUNT(DISTINCT product) as count FROM affects WHERE product IS NOT NULL",
            'severity_stats': """
                SELECT severity, COUNT(*) as count 
                FROM cve 
                WHERE severity IS NOT NULL 
                GROUP BY severity 
                ORDER BY count DESC
            """,
            'year_stats': """
                SELECT substr(public_date, 1, 4) as year, COUNT(*) as count 
                FROM cve 
                WHERE public_date IS NOT NULL AND substr(public_date, 1, 4) != ''
                GROUP BY substr(public_date, 1, 4) 
                ORDER BY year DESC 
                LIMIT 10
            """,
            'state_stats': """
                SELECT state, COUNT(*) as count 
                FROM affects 
                WHERE state IS NOT NULL 
                GROUP BY state 
                ORDER BY count DESC
            """,
            'top_products': """
                SELECT substr(product, 1, 50) as product, COUNT(*) as count 
                FROM affects 
                WHERE product IS NOT NULL 
                GROUP BY product 
                ORDER BY count DESC 
                LIMIT 10
            """
        }
        
        stats_content = [
            "VEX DATABASE COMPREHENSIVE STATISTICS AND OVERVIEW",
            "=" * 60,
            "",
            "This document contains complete statistics about the VEX vulnerability database.",
            "Use this information to answer questions about totals, counts, and distributions.",
            "",
            "COMMON QUESTIONS AND ANSWERS:",
            "- How many CVEs are in the database? Answer: See total CVEs below",
            "- What is the total number of vulnerabilities? Answer: See total CVEs below", 
            "- How many vulnerabilities are there? Answer: See total CVEs below",
            "- What is the CVE count? Answer: See total CVEs below",
            "- How many security issues are tracked? Answer: See total CVEs below",
            "- Database size and statistics? Answer: See totals below",
            ""
        ]
        
        # Get basic counts
        total_cves = pd.read_sql_query(stats_queries['total_cves'], conn).iloc[0]['count']
        total_products = pd.read_sql_query(stats_queries['total_products'], conn).iloc[0]['count']
        unique_products = pd.read_sql_query(stats_queries['unique_products'], conn).iloc[0]['count']
        
        stats_content.extend([
            f"TOTAL RECORDS IN DATABASE:",
            f"- Total CVEs: {total_cves:,} vulnerabilities",
            f"- Total Product Records: {total_products:,} affected product entries",
            f"- Unique Products: {unique_products:,} distinct products",
            ""
        ])
        
        # Severity breakdown
        severity_df = pd.read_sql_query(stats_queries['severity_stats'], conn)
        stats_content.extend([
            "CVE SEVERITY DISTRIBUTION:",
        ])
        for _, row in severity_df.iterrows():
            stats_content.append(f"- {row['severity']}: {row['count']:,} CVEs")
        stats_content.append("")
        
        # Year breakdown
        year_df = pd.read_sql_query(stats_queries['year_stats'], conn)
        stats_content.extend([
            "CVE DISTRIBUTION BY YEAR (Recent 10 years):",
        ])
        for _, row in year_df.iterrows():
            stats_content.append(f"- {row['year']}: {row['count']:,} CVEs")
        stats_content.append("")
        
        # State breakdown
        state_df = pd.read_sql_query(stats_queries['state_stats'], conn)
        stats_content.extend([
            "VULNERABILITY STATES DISTRIBUTION:",
        ])
        for _, row in state_df.iterrows():
            stats_content.append(f"- {row['state']}: {row['count']:,} product records")
        stats_content.append("")
        
        # Top products
        products_df = pd.read_sql_query(stats_queries['top_products'], conn)
        stats_content.extend([
            "TOP 10 MOST AFFECTED PRODUCTS:",
        ])
        for _, row in products_df.iterrows():
            stats_content.append(f"- {row['product']}: {row['count']:,} vulnerability records")
        
        content = "\n".join(stats_content)
        
        metadata = {
            "cve": "DATABASE_STATISTICS",
            "total_cves": int(total_cves),
            "total_products": int(total_products),
            "source": "vex_database_stats",
            "document_type": "statistics"
        }
        
        return Document(page_content=content, metadata=metadata)

class VEXChatbot:
    """RAG-based chatbot for VEX data queries"""
    
    def __init__(self, 
                 db_path: str = "vex.db",
                 model_name: str = "llama3.1",
                 embedding_model: str = "all-MiniLM-L6-v2",
                 vector_db_path: str = "./vex_vectordb",
                 use_huggingface: bool = False,
                 hf_repo_id: str = None):
        
        self.db_path = db_path
        self.model_name = model_name
        self.vector_db_path = vector_db_path
        self.use_huggingface = use_huggingface
        self.hf_repo_id = hf_repo_id
        
        # Initialize components
        self.data_loader = VEXDataLoader(
            db_path=db_path, 
            use_huggingface=use_huggingface, 
            hf_repo_id=hf_repo_id
        )
        self.embeddings = HuggingFaceEmbeddings(model_name=embedding_model)
        self.llm = None
        self.vector_store = None
        self.qa_chain = None
        
        data_source = f"HuggingFace ({hf_repo_id})" if use_huggingface else f"SQLite ({db_path})"
        logger.info(f"Initialized VEX Chatbot with model: {model_name}, data source: {data_source}")
    
    def check_ollama_connection(self) -> bool:
        """Check if Ollama is running and model is available"""
        try:
            import ollama
            # Try to list models
            models_response = ollama.list()
            
            # Handle the ListResponse object structure
            if hasattr(models_response, 'models'):
                models_list = models_response.models
            elif isinstance(models_response, dict) and 'models' in models_response:
                models_list = models_response['models']
            else:
                logger.error("❌ Unexpected response structure from Ollama")
                logger.info("Make sure Ollama is running: ollama serve")
                return False
            
            available_models = []
            
            for model in models_list:
                # Handle Model objects (newer API) or dict structure (older API)
                if hasattr(model, 'model'):
                    available_models.append(model.model)
                elif isinstance(model, dict) and 'model' in model:
                    available_models.append(model['model'])
                elif isinstance(model, dict) and 'name' in model:
                    available_models.append(model['name'])
            
            if not available_models:
                logger.warning("❌ No models found in Ollama")
                logger.info(f"Pull a model first: ollama pull {self.model_name}")
                return False
            
            # Check if our desired model is available (handle versioned models like llama3.1:latest)
            model_found = False
            for model in available_models:
                if self.model_name in model or model.startswith(self.model_name + ":"):
                    model_found = True
                    break
            
            if not model_found:
                logger.warning(f"Model '{self.model_name}' not found. Available models: {available_models}")
                logger.info(f"You can pull the model with: ollama pull {self.model_name}")
                return False
            
            logger.info(f"✅ Ollama connected, model '{self.model_name}' available")
            return True
            
        except ImportError:
            logger.error("❌ Ollama Python package not installed")
            logger.info("Install with: pip install ollama")
            return False
        except Exception as e:
            logger.error(f"❌ Ollama connection failed: {e}")
            logger.info("Make sure Ollama is installed and running:")
            logger.info("1. Install: https://ollama.ai/")
            logger.info("2. Start: ollama serve")
            logger.info(f"3. Pull model: ollama pull {self.model_name}")
            return False
    
    def setup_vector_store(self, force_rebuild: bool = False) -> None:
        """Setup or load vector store with VEX data"""
        
        if Path(self.vector_db_path).exists() and not force_rebuild:
            logger.info("Loading existing vector store...")
            self.vector_store = Chroma(
                persist_directory=self.vector_db_path,
                embedding_function=self.embeddings
            )
            logger.info(f"✅ Loaded vector store with {self.vector_store._collection.count()} documents")
        else:
            logger.info("Creating new vector store...")
            documents = self.data_loader.load_vex_data()
            
            # Split documents if they're too large
            text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=1000,
                chunk_overlap=200,
                length_function=len,
            )
            split_docs = text_splitter.split_documents(documents)
            
            # Create vector store
            self.vector_store = Chroma.from_documents(
                documents=split_docs,
                embedding=self.embeddings,
                persist_directory=self.vector_db_path
            )
            
            logger.info(f"✅ Created vector store with {len(split_docs)} document chunks")
    
    def setup_llm(self) -> None:
        """Setup local LLM connection"""
        if not self.check_ollama_connection():
            raise ConnectionError("Cannot connect to Ollama. Please check the setup instructions above.")
        
        self.llm = OllamaLLM(model=self.model_name)
        logger.info("✅ LLM connection established")
    
    def setup_qa_chain(self) -> None:
        """Setup the question-answering chain"""
        
        # Custom prompt template for VEX data
        template = """You are a cybersecurity expert assistant specializing in VEX (Vulnerability Exploitability eXchange) data analysis. 
        Use the following context about CVEs and vulnerabilities to answer the question accurately and comprehensively.

        Context:
        {context}

        Question: {question}

        Instructions:
        - IMPORTANT: If you see a "VEX DATABASE COMPREHENSIVE STATISTICS" document in the context, use those exact numbers for database totals and statistics
        - For statistical questions (totals, counts, distributions), prioritize the statistics document over individual CVE records
        - For specific CVE questions, focus on the individual CVE documents
        - Include CVE IDs, CVSS scores, and severity levels when relevant
        - Mention affected products and components when applicable
        - When providing counts or statistics, always specify the source (e.g., "According to the database statistics...")
        - If asked about database totals and you have the statistics document, use those authoritative numbers
        - Format your response clearly with bullet points or structured data when appropriate
        - Be specific about the scope of your knowledge based on the retrieved context

        Answer:"""

        prompt = PromptTemplate(template=template, input_variables=["context", "question"])
        
        # Create retrieval QA chain with improved retrieval
        self.qa_chain = RetrievalQA.from_chain_type(
            llm=self.llm,
            chain_type="stuff",
            retriever=self.vector_store.as_retriever(
                search_kwargs={"k": 20}  # Retrieve more documents for better context
            ),
            chain_type_kwargs={"prompt": prompt},
            return_source_documents=True
        )
        
        logger.info("✅ QA chain configured")
    
    def initialize(self, force_rebuild_vectors: bool = False) -> None:
        """Initialize all components"""
        logger.info("Initializing VEX Chatbot...")
        
        try:
            self.setup_vector_store(force_rebuild_vectors)
            self.setup_llm()
            self.setup_qa_chain()
            logger.info("🚀 VEX Chatbot ready!")
            
        except Exception as e:
            logger.error(f"❌ Initialization failed: {e}")
            raise
    
    def query(self, question: str, include_sources: bool = False) -> Dict[str, Any]:
        """Ask a question and get an answer with sources"""
        if not self.qa_chain:
            raise RuntimeError("Chatbot not initialized. Call initialize() first.")
        
        logger.info(f"Processing query: {question[:100]}...")
        
        try:
            # Check if this is a statistical query that should use database stats
            if self._is_statistical_query(question):
                return self._handle_statistical_query(question, include_sources)
            
            result = self.qa_chain({"query": question})
            
            response = {
                "question": question,
                "answer": result["result"],
                "sources": []
            }
            
            if include_sources and "source_documents" in result:
                for doc in result["source_documents"]:
                    source_info = {
                        "content": doc.page_content[:200] + "..." if len(doc.page_content) > 200 else doc.page_content,
                        "metadata": doc.metadata
                    }
                    response["sources"].append(source_info)
            
            return response
            
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return {
                "question": question,
                "answer": f"Sorry, I encountered an error processing your question: {str(e)}",
                "sources": []
            }
    
    def _is_statistical_query(self, question: str) -> bool:
        """Check if the question is asking for database statistics"""
        statistical_keywords = [
            "how many", "total", "count", "number of", "statistics", 
            "distribution", "breakdown", "overview", "database size"
        ]
        question_lower = question.lower()
        return any(keyword in question_lower for keyword in statistical_keywords)
    
    def _handle_statistical_query(self, question: str, include_sources: bool = False) -> Dict[str, Any]:
        """Handle statistical queries with direct database statistics"""
        try:
            # Get fresh database statistics directly
            db_stats = self.get_stats()
            
            # Create comprehensive statistics context
            stats_context = f"""VEX DATABASE COMPREHENSIVE STATISTICS:

TOTAL RECORDS IN DATABASE:
- Total CVEs: {db_stats['total_cves']:,} vulnerabilities
- Total Product Records: {db_stats['total_affected_products']:,} affected product entries

CVE SEVERITY DISTRIBUTION:"""
            
            for item in db_stats['by_severity']:
                stats_context += f"\n- {item['severity']}: {item['count']:,} CVEs"
            
            stats_context += "\n\nCVE DISTRIBUTION BY YEAR (Recent years):"
            for item in db_stats['by_year']:
                stats_context += f"\n- {item['year']}: {item['count']:,} CVEs"
            
            # Create a direct prompt for statistical queries
            prompt = f"""You are a cybersecurity expert assistant specializing in VEX vulnerability data analysis.

Context (Current Database Statistics):
{stats_context}

Question: {question}

Instructions:
- Use the database statistics provided above to answer the question accurately
- Provide specific numbers from the statistics when available
- If asked for totals or counts, use the exact numbers from the TOTAL RECORDS section
- Format your response clearly with specific data points
- When mentioning totals, specify "According to the current database statistics"

Answer:"""

            # Use the LLM directly for this statistical query
            response_text = self.llm.invoke(prompt)
            
            response = {
                "question": question,
                "answer": response_text,
                "sources": [{
                    "content": f"Database Statistics: {db_stats['total_cves']:,} total CVEs, {db_stats['total_affected_products']:,} product records",
                    "metadata": {
                        "source": "live_database_query",
                        "total_cves": db_stats['total_cves'],
                        "query_time": "real-time"
                    }
                }] if include_sources else []
            }
            
            return response
                
        except Exception as e:
            logger.error(f"Statistical query handling failed: {e}")
            return self._fallback_to_regular_rag(question, include_sources)
    
    def _fallback_to_regular_rag(self, question: str, include_sources: bool = False) -> Dict[str, Any]:
        """Fallback to regular RAG processing"""
        result = self.qa_chain({"query": question})
        
        response = {
            "question": question,
            "answer": result["result"],
            "sources": []
        }
        
        if include_sources and "source_documents" in result:
            for doc in result["source_documents"]:
                source_info = {
                    "content": doc.page_content[:200] + "..." if len(doc.page_content) > 200 else doc.page_content,
                    "metadata": doc.metadata
                }
                response["sources"].append(source_info)
        
        return response
    
    def get_stats(self) -> Dict[str, Any]:
        """Get basic statistics about the VEX database"""
        conn = sqlite3.connect(self.db_path)
        
        stats = {}
        try:
            # Total CVEs
            stats["total_cves"] = pd.read_sql_query("SELECT COUNT(*) as count FROM cve", conn).iloc[0]["count"]
            
            # CVEs by severity
            severity_stats = pd.read_sql_query("""
                SELECT severity, COUNT(*) as count 
                FROM cve 
                WHERE severity IS NOT NULL 
                GROUP BY severity 
                ORDER BY count DESC
            """, conn)
            stats["by_severity"] = severity_stats.to_dict('records')
            
            # CVEs by year
            year_stats = pd.read_sql_query("""
                SELECT substr(public_date, 1, 4) as year, COUNT(*) as count 
                FROM cve 
                WHERE public_date IS NOT NULL 
                GROUP BY substr(public_date, 1, 4) 
                ORDER BY year DESC 
                LIMIT 10
            """, conn)
            stats["by_year"] = year_stats.to_dict('records')
            
            # Affected products count
            stats["total_affected_products"] = pd.read_sql_query("SELECT COUNT(*) as count FROM affects", conn).iloc[0]["count"]
            
        finally:
            conn.close()
            
        return stats

def main():
    """CLI interface for the VEX chatbot"""
    parser = argparse.ArgumentParser(
        description="VEX Data Chatbot - Query vulnerability data using natural language",
        epilog="""
Examples:
  %(prog)s --query "What are the most critical CVEs from 2024?"
  %(prog)s --query "Show me CVEs affecting OpenSSL" --sources
  %(prog)s --stats
  %(prog)s --huggingface --hf-repo-id "username/vex-dataset" --query "How many CVEs?"
  %(prog)s --rebuild-vectors  # Rebuild the vector database
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--query", "-q", help="Ask a question about VEX data")
    parser.add_argument("--sources", "-s", action="store_true", help="Include source documents in response")
    parser.add_argument("--stats", action="store_true", help="Show database statistics")
    parser.add_argument("--model", "-m", default="llama3.1", help="Ollama model to use (default: llama3.1)")
    parser.add_argument("--database", "-d", default="vex.db", help="Path to VEX database (default: vex.db)")
    parser.add_argument("--huggingface", "--hf", action="store_true", help="Use HuggingFace dataset instead of SQLite")
    parser.add_argument("--hf-repo-id", help="HuggingFace repository ID (e.g., 'username/vex-dataset')")
    parser.add_argument("--rebuild-vectors", action="store_true", help="Force rebuild of vector database")
    parser.add_argument("--interactive", "-i", action="store_true", help="Start interactive chat session")
    
    args = parser.parse_args()
    
    # Validate HuggingFace arguments
    if args.huggingface and not args.hf_repo_id:
        print("❌ Error: --hf-repo-id is required when using --huggingface")
        sys.exit(1)
    
    # Create chatbot instance
    try:
        chatbot = VEXChatbot(
            db_path=args.database,
            model_name=args.model,
            use_huggingface=args.huggingface,
            hf_repo_id=args.hf_repo_id
        )
        
        # Initialize
        chatbot.initialize(force_rebuild_vectors=args.rebuild_vectors)
        
        if args.stats:
            print("📊 VEX Database Statistics")
            print("=" * 50)
            stats = chatbot.get_stats()
            
            print(f"Total CVEs: {stats['total_cves']:,}")
            print(f"Total Affected Products: {stats['total_affected_products']:,}")
            
            print("\n📈 CVEs by Severity:")
            for item in stats['by_severity']:
                print(f"  {item['severity']}: {item['count']:,}")
            
            print("\n📅 Recent CVEs by Year:")
            for item in stats['by_year']:
                print(f"  {item['year']}: {item['count']:,}")
            
        elif args.query:
            print(f"🤖 Processing your question...")
            result = chatbot.query(args.query, include_sources=args.sources)
            
            print(f"\n❓ Question: {result['question']}")
            print(f"\n✅ Answer:\n{result['answer']}")
            
            if args.sources and result['sources']:
                print(f"\n📚 Sources ({len(result['sources'])}):")
                for i, source in enumerate(result['sources'], 1):
                    print(f"  {i}. CVE: {source['metadata'].get('cve', 'N/A')}")
                    print(f"     {source['content']}")
                    print()
        
        elif args.interactive:
            print("🤖 VEX Chatbot Interactive Mode")
            print("Ask questions about vulnerability data. Type 'quit' to exit.")
            print("=" * 60)
            
            while True:
                try:
                    question = input("\n💬 Your question: ").strip()
                    if question.lower() in ['quit', 'exit', 'q']:
                        break
                    
                    if not question:
                        continue
                    
                    result = chatbot.query(question)
                    print(f"\n🤖 Answer:\n{result['answer']}\n")
                    
                except KeyboardInterrupt:
                    print("\n👋 Goodbye!")
                    break
                    
        else:
            parser.print_help()
            
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 