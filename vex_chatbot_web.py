#!/usr/bin/env python3
"""
VEX Chatbot Web Interface - Streamlit-based web UI for the VEX data chatbot
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import sqlite3
from pathlib import Path
import sys
import os

# Import our chatbot
from vex_chatbot import VEXChatbot

# Configure Streamlit page
st.set_page_config(
    page_title="VEX Data Chatbot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .chat-message {
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
        display: flex;
        flex-direction: column;
    }
    .user-message {
        background-color: #007ACC;
        color: white;
        align-self: flex-end;
        max-width: 80%;
    }
    .bot-message {
        background-color: #F0F2F6;
        color: #262730;
        align-self: flex-start;
        max-width: 80%;
    }
    .source-doc {
        background-color: #FFF9E6;
        border-left: 4px solid #FFB800;
        padding: 0.5rem;
        margin: 0.5rem 0;
        border-radius: 0.25rem;
    }
</style>
""", unsafe_allow_html=True)

# Chatbot initialization now handled in main flow

def load_database_stats():
    """Load and cache database statistics"""
    if 'stats' not in st.session_state:
        try:
            db_path = st.session_state.get('db_path', 'vex.db')
            if not Path(db_path).exists():
                st.warning(f"Database {db_path} not found!")
                return None
            
            conn = sqlite3.connect(db_path)
            
            # Load comprehensive stats
            stats = {}
            
            # Basic counts
            stats['total_cves'] = pd.read_sql_query("SELECT COUNT(*) as count FROM cve", conn).iloc[0]['count']
            stats['total_products'] = pd.read_sql_query("SELECT COUNT(*) as count FROM affects", conn).iloc[0]['count']
            
            # Severity distribution
            stats['severity_df'] = pd.read_sql_query("""
                SELECT severity, COUNT(*) as count 
                FROM cve 
                WHERE severity IS NOT NULL 
                GROUP BY severity 
                ORDER BY count DESC
            """, conn)
            
            # CVEs by year
            stats['year_df'] = pd.read_sql_query("""
                SELECT substr(public_date, 1, 4) as year, COUNT(*) as count 
                FROM cve 
                WHERE public_date IS NOT NULL AND year != '' 
                GROUP BY year 
                ORDER BY year DESC
            """, conn)
            
            # Top affected products
            stats['products_df'] = pd.read_sql_query("""
                SELECT substr(product, 1, 50) as product_short, COUNT(*) as count 
                FROM affects 
                WHERE product IS NOT NULL 
                GROUP BY product_short 
                ORDER BY count DESC 
                LIMIT 15
            """, conn)
            
            # Vulnerability states
            stats['states_df'] = pd.read_sql_query("""
                SELECT state, COUNT(*) as count 
                FROM affects 
                WHERE state IS NOT NULL 
                GROUP BY state 
                ORDER BY count DESC
            """, conn)
            
            conn.close()
            st.session_state.stats = stats
            
        except Exception as e:
            st.error(f"Error loading database stats: {e}")
            return None
    
    return st.session_state.stats

def create_charts(stats):
    """Create visualization charts"""
    col1, col2 = st.columns(2)
    
    with col1:
        # Severity pie chart
        if not stats['severity_df'].empty:
            fig_severity = px.pie(
                stats['severity_df'], 
                values='count', 
                names='severity',
                title="CVEs by Severity",
                color_discrete_map={
                    'Critical': '#FF4B4B',
                    'Important': '#FF8C00', 
                    'Moderate': '#FFD700',
                    'Low': '#32CD32'
                }
            )
            st.plotly_chart(fig_severity, use_container_width=True)
    
    with col2:
        # CVEs by year bar chart
        if not stats['year_df'].empty:
            fig_year = px.bar(
                stats['year_df'].head(10), 
                x='year', 
                y='count',
                title="CVEs by Year (Last 10 Years)",
                color='count',
                color_continuous_scale='Blues'
            )
            fig_year.update_layout(showlegend=False)
            st.plotly_chart(fig_year, use_container_width=True)
    
    # Vulnerability states
    col3, col4 = st.columns(2)
    
    with col3:
        if not stats['states_df'].empty:
            fig_states = px.bar(
                stats['states_df'], 
                x='state', 
                y='count',
                title="Vulnerability States",
                color='state',
                color_discrete_map={
                    'fixed': '#28A745',
                    'affected': '#DC3545',
                    'not_affected': '#6C757D',
                    'wontfix': '#FFC107'
                }
            )
            st.plotly_chart(fig_states, use_container_width=True)
    
    with col4:
        # Top products
        if not stats['products_df'].empty:
            fig_products = px.bar(
                stats['products_df'].head(10), 
                x='count', 
                y='product_short',
                orientation='h',
                title="Top 10 Most Affected Products",
                color='count',
                color_continuous_scale='Reds'
            )
            fig_products.update_layout(showlegend=False)
            st.plotly_chart(fig_products, use_container_width=True)

def render_chat_message(message, is_user=False):
    """Render a chat message with styling"""
    css_class = "user-message" if is_user else "bot-message"
    icon = "👤" if is_user else "🤖"
    
    st.markdown(f"""
    <div class="chat-message {css_class}">
        <strong>{icon} {'You' if is_user else 'VEX Assistant'}</strong><br>
        {message}
    </div>
    """, unsafe_allow_html=True)

def main():
    st.title("🛡️ VEX Data Chatbot")
    st.markdown("*Query vulnerability data using natural language*")
    
    # Configuration sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Data source selection
        data_source = st.radio(
            "Data Source:",
            ["SQLite Database", "HuggingFace Dataset"],
            help="Choose between local SQLite database or HuggingFace dataset"
        )
        
        if data_source == "SQLite Database":
            db_path = st.text_input(
                "Database Path:",
                value="vex.db",
                help="Path to the VEX SQLite database file"
            )
            use_hf = False
            hf_repo_id = None
        else:
            hf_repo_id = st.text_input(
                "HuggingFace Repository ID:",
                value="",
                placeholder="username/vex-dataset",
                help="HuggingFace repository ID (e.g., 'username/vex-dataset')"
            )
            db_path = "vex.db"  # Still needed for initialization
            use_hf = True
        
        # Model selection
        model_name = st.selectbox(
            "LLM Model:",
            ["llama3.1", "llama2", "mistral", "codellama"],
            help="Choose the Ollama model for responses"
        )
        
        # Vector database options
        rebuild_vectors = st.checkbox(
            "Rebuild Vector Database",
            help="Force rebuild the vector embeddings (takes time)"
        )

    # Initialize chatbot if not already done or if configuration changed
    config_key = f"{data_source}_{db_path}_{hf_repo_id}_{model_name}"
    if "chatbot" not in st.session_state or st.session_state.get("config_key") != config_key:
        if data_source == "HuggingFace Dataset" and not hf_repo_id:
            st.error("Please provide a HuggingFace repository ID when using HuggingFace dataset")
            st.stop()
        
        try:
            with st.spinner("🚀 Initializing VEX Chatbot..."):
                st.session_state.chatbot = VEXChatbot(
                    db_path=db_path,
                    model_name=model_name,
                    use_huggingface=use_hf,
                    hf_repo_id=hf_repo_id
                )
                st.session_state.chatbot.initialize(force_rebuild_vectors=rebuild_vectors)
                st.session_state.config_key = config_key
                
            st.success("✅ Chatbot initialized successfully!")
        except Exception as e:
            st.error(f"❌ Failed to initialize chatbot: {str(e)}")
            st.stop()
    
    # Main content area
    tab1, tab2, tab3 = st.tabs(["💬 Chat", "📊 Analytics", "ℹ️ Help"])
    
    with tab1:
        # Chat interface
        # Initialize chat history
        if 'chat_history' not in st.session_state:
            st.session_state.chat_history = []
        
        # Display chat history
        chat_container = st.container()
        with chat_container:
            for message in st.session_state.chat_history:
                render_chat_message(message['content'], message['is_user'])
                
                # Show sources if available
                if not message['is_user'] and 'sources' in message:
                    with st.expander(f"📚 Sources ({len(message['sources'])})", expanded=False):
                        for i, source in enumerate(message['sources'], 1):
                            st.markdown(f"""
                            <div class="source-doc">
                                <strong>Source {i}: {source['metadata'].get('cve', 'N/A')}</strong><br>
                                {source['content']}
                            </div>
                            """, unsafe_allow_html=True)
        
        # Chat input
        st.markdown("---")
        col1, col2, col3 = st.columns([6, 1, 1])
        
        with col1:
            user_input = st.text_input(
                "Ask a question about VEX data:",
                placeholder="e.g., What are the most critical CVEs from 2024?",
                key="chat_input"
            )
        
        with col2:
            include_sources = st.checkbox("Sources", value=False)
        
        with col3:
            send_button = st.button("Send", type="primary")
        
        # Example questions
        st.markdown("**💡 Example questions:**")
        example_col1, example_col2 = st.columns(2)
        
        # Track if an example button was clicked
        example_query = None
        
        with example_col1:
            if st.button("🔍 Show critical CVEs from 2024"):
                example_query = "What are the most critical CVEs from 2024?"
                
            if st.button("📈 Vulnerability statistics by severity"):
                example_query = "Give me statistics about vulnerabilities by severity level"
        
        with example_col2:
            if st.button("🐧 Linux kernel vulnerabilities"):
                example_query = "Show me recent CVEs affecting the Linux kernel"
                
            if st.button("🔒 OpenSSL security issues"):
                example_query = "What CVEs affect OpenSSL components?"
        
        # Determine the query to process
        query_to_process = None
        if example_query:
            query_to_process = example_query
        elif send_button and user_input and user_input.strip():
            query_to_process = user_input.strip()
        
        # Process user input
        if query_to_process:
            # Add user message to history
            st.session_state.chat_history.append({
                'content': query_to_process,
                'is_user': True
            })
            
            # Get bot response
            with st.spinner("🤖 Thinking..."):
                try:
                    result = st.session_state.chatbot.query(query_to_process, include_sources=include_sources)
                    
                    bot_message = {
                        'content': result['answer'],
                        'is_user': False
                    }
                    
                    if include_sources and result['sources']:
                        bot_message['sources'] = result['sources']
                    
                    st.session_state.chat_history.append(bot_message)
                    
                except Exception as e:
                    st.session_state.chat_history.append({
                        'content': f"Sorry, I encountered an error: {str(e)}",
                        'is_user': False
                    })
            
            # Rerun to refresh the interface
            st.rerun()
        
        # Clear chat button
        if st.button("🗑️ Clear Chat History"):
            st.session_state.chat_history = []
            st.rerun()
    
    with tab2:
        # Analytics tab
        st.header("📊 VEX Database Analytics")
        
        stats = load_database_stats()
        if stats:
            # Key metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total CVEs", f"{stats['total_cves']:,}")
            with col2:
                st.metric("Affected Products", f"{stats['total_products']:,}")
            with col3:
                if not stats['severity_df'].empty:
                    critical_count = stats['severity_df'][stats['severity_df']['severity'] == 'Critical']['count'].sum()
                    st.metric("Critical CVEs", f"{critical_count:,}")
            with col4:
                if not stats['year_df'].empty:
                    current_year = str(datetime.now().year)
                    current_year_count = stats['year_df'][stats['year_df']['year'] == current_year]['count'].sum()
                    st.metric(f"{current_year} CVEs", f"{current_year_count:,}")
            
            st.markdown("---")
            
            # Charts
            create_charts(stats)
            
            # Data tables
            st.header("📋 Detailed Data")
            
            table_col1, table_col2 = st.columns(2)
            
            with table_col1:
                st.subheader("CVEs by Severity")
                st.dataframe(stats['severity_df'], use_container_width=True)
                
                st.subheader("Vulnerability States")
                st.dataframe(stats['states_df'], use_container_width=True)
            
            with table_col2:
                st.subheader("CVEs by Year")
                st.dataframe(stats['year_df'].head(10), use_container_width=True)
                
                st.subheader("Top Affected Products")
                st.dataframe(stats['products_df'].head(10), use_container_width=True)
        
        else:
            st.warning("Could not load database statistics. Make sure your VEX database is available.")
    
    with tab3:
        # Help tab
        st.header("ℹ️ How to Use the VEX Chatbot")
        
        st.markdown("""
        ### 🚀 Getting Started
        
        1. **Setup Ollama**: Install from [https://ollama.ai/](https://ollama.ai/)
        2. **Start Ollama**: Run `ollama serve` in terminal
        3. **Pull a Model**: Run `ollama pull llama3.1`
        4. **Verify Database**: Make sure your VEX database file exists
        
        ### 💬 Asking Questions
        
        The chatbot can help you with:
        
        - **CVE Information**: "Tell me about CVE-2024-1234"
        - **Statistics**: "How many critical CVEs were there in 2024?"
        - **Product Analysis**: "What vulnerabilities affect Red Hat Enterprise Linux?"
        - **Trend Analysis**: "Show me vulnerability trends over the years"
        - **Component Search**: "Find CVEs affecting OpenSSL"
        
        ### 🎯 Example Queries
        
        ```
        What are the most severe vulnerabilities from 2024?
        Show me all CVEs affecting kernel components
        How many vulnerabilities are fixed vs unfixed?
        What products have the most security issues?
        Find CVEs with CVSS score above 9.0
        ```
        
        ### 🔧 Configuration
        
        - **Database Path**: Point to your VEX SQLite database
        - **LLM Model**: Choose from available Ollama models
        - **Sources**: Enable to see supporting documents
        - **Vector Rebuild**: Refresh if you update your database
        
        ### 📊 Analytics Features
        
        - Interactive charts and visualizations
        - Severity distribution analysis
        - Year-over-year vulnerability trends
        - Product impact analysis
        - Vulnerability state tracking
        
        ### 🛠️ Troubleshooting
        
        - **Connection Error**: Check if Ollama is running
        - **Model Not Found**: Pull the model with `ollama pull <model_name>`
        - **Database Error**: Verify the database path and file permissions
        - **Slow Response**: Consider using a smaller/faster model
        """)

if __name__ == "__main__":
    main() 