import sys
import json
from typing import Any

# The user provided path: /Users/foxleoly/.lmstudio/models/chaoliangUNSW/Jev-Style-Qwen3.5-2B-Decision-MLX-bf16
MODEL_PATH = "/Users/foxleoly/.lmstudio/models/chaoliangUNSW/Jev-Style-Qwen3.5-2B-Decision-MLX-bf16"

# Add model path to sys.path so jev_style_mlx can be imported
sys.path.append(MODEL_PATH)

try:
    from jev_style_mlx import JevStyle
except ImportError as e:
    print(f"Error importing JevStyle from {MODEL_PATH}: {e}")
    sys.exit(1)

class Jev2bService:
    def __init__(self, model_path: str):
        self.model = JevStyle(model_path)

    def handle_request(self, request_data: dict[str, Any]) -> dict[str, Any]:
        """
        Implements the systemone contract:
        Request: {model, state, questions:{name:{type:'choice'|'noul',instructions,criteria:{opt:desc}}}}
        Response: {answers:{name:{choice,confidence,probabilities:{safe/risky/destructive:p}}}}
        """
        try:
            state = request_data.get("state", "")
            questions = request_data.get("questions", {})

            answers = {}

            for q_name, q_info in questions.items():
                q_type = q_info.get("type", "choice")
                instructions = q_info.get("instructions", "")
                
                if q_type == "choice":
                    options = list(q_info.get("criteria", {}).keys())
                    # JevStyle: decide(state, question, options) -> [(opt, p)]
                    decisions = self.model.decide(state, instructions, options)
                    
                    best_choice = None
                    max_p = 0.0
                    if decisions:
                        # Sort by probability descending to find the top one
                        decisions.sort(key=lambda x: x[1], reverse=True)
                        best_choice = decisions[0][0]
                        max_p = decisions[0][1]

                    # The contract requires probabilities to have safe/risky/destructive keys.
                    probs = {"safe": 0.0, "risky": 0.0, "destructive": 0.0}
                    if best_choice in probs:
                        probs[best_choice] = max_p

                    answers[q_name] = {
                        "choice": best_choice,
                        "confidence": max_p,
                        "probabilities": probs
                    }

                elif q_type == "noul":
                    res = self.model.decide_bool(state, instructions)
                    probs = {"safe": 1.0 if res else 0.0, "risky": 0.0, "destructive": 0.0}
                    answers[q_name] = {
                        "choice": "yes" if res else "no",
                        "confidence": 1.0,
                        "probabilities": probs
                    }

            return {"answers": answers}

        except Exception as e:
            return {"type": "refusal", "error": str(e)}

if __name__ == "__main__":
    # For testing via: python service.py '{"state": "...", "questions": {...}}'
    if len(sys.argv) > 1:
        try:
            service = Jev2bService(MODEL_PATH)
            print(json.dumps(service.handle_request(json.loads(sys.argv[1])), indent=2))
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
