# import os

from openai import OpenAI


class QualitativeEvaluator:
    def __init__(self, api_key):
        self.client = OpenAI(api_key=api_key)

    def evaluate(self, code_snippet, rubric_description):
        """
        Sends the code and rubric to OpenAI to perform
        a qualitative assessment.
        """
        prompt = f"""
        You are an expert code reviewer. Evaluate the following code snippet
        against the provided qualitative rubric.

        ### CODE SNIPPET:
        {code_snippet}

        ### RUBRIC:
        {rubric_description}

        ### INSTRUCTIONS:
        - Analyze the code qualitatively (style, logic, structure, readability).
        - For each point in the rubric, provide a score (1-5) and a brief justification.
        - Output the result in a structured JSON format.
        """

        response = self.client.chat.completions.create(
            model="gpt-4o", # Or gpt-4-turbo
            messages=[
                {"role": "system", "content": "You are a precise technical evaluator."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )

        return response.choices[0].message.content

# --- Example Usage ---
if __name__ == "__main__":
    # 1. Define your qualitative rubric
    rubric = """
    1. Readability: Does the code follow PEP8 standards and use meaningful variable names?
    2. Modularity: Is the code broken down into logical, reusable functions?
    3. Idiomatic Usage: Does the code use Pythonic patterns effectively?
    """

    # 2. Your IDB / Code snippet
    idb_code = """
    def g(x):
        return x*x
    print(g(5))
    """

    # 3. Initialize and Run
    evaluator = QualitativeEvaluator(api_key="YOUR_OPENAI_API_KEY")
    report = evaluator.evaluate(idb_code, rubric)

    print(report)
