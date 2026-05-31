import chromadb

client = chromadb.PersistentClient(path="./vector_db")

collection = client.get_or_create_collection(
    name="security_logs"
)

def insert_log(doc_id, text):
    collection.add(
        ids=[doc_id],
        documents=[text]
    )

def search_logs(query):
    return collection.query(
        query_texts=[query],
        n_results=5
    )