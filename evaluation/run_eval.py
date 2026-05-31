import time
import pandas as pd

from chatbot.retrieval.questions import (
    TEST_QUESTIONS
)

from chatbot.retrieval.nl2sparql import (
    execute_question
)


def evaluate():

    results = []

    for question in TEST_QUESTIONS:

        start = time.time()

        try:

            response = execute_question(question)

            latency = time.time() - start

            results.append({
                "question": question,
                "status": "success",
                "latency": latency
            })

        except Exception as e:

            results.append({
                "question": question,
                "status": "failed",
                "error": str(e)
            })

    df = pd.DataFrame(results)

    print(df)

    df.to_csv("evaluation_results.csv", index=False)

if __name__ == "__main__":
    evaluate()