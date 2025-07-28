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
    """Load and prepare VEX data from SQLite database"""
    
    def __init__(self, db_path: str = "vex.db"):
        self.db_path = db_path
        if not Path(db_path).exists():
            raise FileNotFoundError(f"Database file '{db_path}' not found!")
    
    def load_vex_data(self) -> List[Document]:
        """Load VEX data and convert to langchain Documents"""
        logger.info("Loading VEX data from database...")
        
        conn = sqlite3.connect(self.db_path)
        
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
        
        documents = []
        for _, row in df.iterrows():
            # Create comprehensive document content
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
                "cve": row['cve'],
                "cvss_score": row['cvss_score'],
                "severity": row['severity'],
                "public_date": row['public_date'],
                "source": "vex_database"
            }
            
            documents.append(Document(page_content=content, metadata=metadata))
        
        logger.info(f"Loaded {len(documents)} VEX documents")
        return documents

class VEXChatbot:
    """RAG-based chatbot for VEX data queries"""
    
    def __init__(self, 
                 db_path: str = "vex.db",
                 model_name: str = "llama3.1",
                 embedding_model: str = "all-MiniLM-L6-v2",
                 vector_db_path: str = "./vex_vectordb"):
        
        self.db_path = db_path
        self.model_name = model_name
        self.vector_db_path = vector_db_path
        
        # Initialize components
        self.data_loader = VEXDataLoader(db_path)
        self.embeddings = HuggingFaceEmbeddings(model_name=embedding_model)
        self.llm = None
        self.vector_store = None
        self.qa_chain = None
        
        logger.info(f"Initialized VEX Chatbot with model: {model_name}")
    
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
        - Provide specific, accurate information based on the context
        - Include CVE IDs, CVSS scores, and severity levels when relevant
        - Mention affected products and components when applicable
        - If asked for statistics, calculate them from the provided data
        - If the context doesn't contain enough information, say so clearly
        - Format your response clearly with bullet points or structured data when appropriate

        Answer:"""

        prompt = PromptTemplate(template=template, input_variables=["context", "question"])
        
        # Create retrieval QA chain
        self.qa_chain = RetrievalQA.from_chain_type(
            llm=self.llm,
            chain_type="stuff",
            retriever=self.vector_store.as_retriever(search_kwargs={"k": 10}),
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
  %(prog)s --rebuild-vectors  # Rebuild the vector database
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--query", "-q", help="Ask a question about VEX data")
    parser.add_argument("--sources", "-s", action="store_true", help="Include source documents in response")
    parser.add_argument("--stats", action="store_true", help="Show database statistics")
    parser.add_argument("--model", "-m", default="llama3.1", help="Ollama model to use (default: llama3.1)")
    parser.add_argument("--database", "-d", default="vex.db", help="Path to VEX database (default: vex.db)")
    parser.add_argument("--rebuild-vectors", action="store_true", help="Force rebuild of vector database")
    parser.add_argument("--interactive", "-i", action="store_true", help="Start interactive chat session")
    
    args = parser.parse_args()
    
    # Create chatbot instance
    try:
        chatbot = VEXChatbot(
            db_path=args.database,
            model_name=args.model
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