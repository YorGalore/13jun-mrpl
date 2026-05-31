from langchain.prompts import PromptTemplate
from langchain_openai import ChatOpenAI

from chatbot.api.sparql_client import run_query, bindings_to_rows
from chatbot.retrieval.ontology_context import ONTOLOGY_CONTEXT

llm = ChatOpenAI(
    model="gpt-4o-mini",
    temperature=0
)

template = """
You are a cybersecurity SPARQL expert.

Convert the following natural language question into a valid SPARQL query.

Ontology:
{ontology}

Question:
{question}

Only return SPARQL query.
"""

prompt = PromptTemplate(
    input_variables=["ontology", "question"],
    template=template
)

def generate_sparql(question: str) -> str:
    chain = prompt | llm
    response = chain.invoke({
        "ontology": ONTOLOGY_CONTEXT,
        "question": question
    })

    return response.content.strip()


def execute_question(question: str):
    sparql_query = generate_sparql(question)

    result = run_query(sparql_query)
    
    rows = bindings_to_rows(result)

    return {
        "question": question,
        "sparql": sparql_query,
        "results": rows
    }


if __name__ == "__main__":

    q = "Show vulnerabilities related to CVE-2021-44228"

    result = execute_nl_query(q)

    print("QUESTION:")
    print(result["question"])

    print("\nSPARQL:")
    print(result["sparql"])

    print("\nRESULTS:")
    for r in result["results"]:
        print(r)