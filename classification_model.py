import numpy as np
import tensorflow as tf
from transformers import TFRobertaModel, RobertaTokenizer



class CodePreprocessor:
    """Handles all code preprocessing tasks"""

    @staticmethod
    def remove_whitespaces(java_code):
        import re
        if not isinstance(java_code, str):
            return java_code
        return re.sub(r'^\s*$\n?', '', java_code, flags=re.MULTILINE)

    @staticmethod
    def remove_comments(java_code):
        import re
        if not isinstance(java_code, str):
            return java_code

        pattern = r"""
            ("(?:\\.|[^"\\])*")|      # Doublequoted strings
            ('(?:\\.|[^'\\])*')|      # Singlequoted chars
            (//.*?$)|                 # Singleline comments
            (/\*.*?\*/)               # Multiline comments
        """

        def replacer(match):
            if match.group(1) or match.group(2):
                return match.group(0)
            return ""

        lines = []
        for line in java_code.splitlines():
            processed = re.sub(pattern, replacer, line, flags=re.VERBOSE | re.DOTALL)
            lines.append(processed)

        result = "\n".join(lines)
        result = re.sub(r"/\*.*?\*/", "", result, flags=re.DOTALL)
        return result

    def preprocess(self, code):
        """full preprocessing pipeline"""
        code = self.remove_whitespaces(code)
        code = self.remove_comments(code)
        return code.strip()


class EmbeddingGenerator:
    """Handler for code embedding generation using graphCodeBERT"""

    def __init__(self, model_path=None):
        if model_path: # if fine-tuned model exists
            self.load(model_path)
        else:
            self.tokenizer = RobertaTokenizer.from_pretrained("microsoft/graphcodebert-base")
            self.model = TFRobertaModel.from_pretrained("microsoft/graphcodebert-base")

    def generate_embedding(self, code):
        """Generate embedding for a single code snippet"""
        inputs = self.tokenizer(code, return_tensors="tf", padding=True, truncation=True, max_length=512)
        outputs = self.model(inputs)
        return tf.reduce_mean(outputs.last_hidden_state, axis=1).numpy().flatten()

    def generate_embeddings_batch(self, code_list):
        return np.array([self.generate_embedding(code) for code in code_list])

    def load(self, path):
        self.tokenizer = RobertaTokenizer.from_pretrained(path)
        self.model = TFRobertaModel.from_pretrained(path)


class VulnerabilityDetectionModel:
    """The main model for vulnerability detection used in the system"""

    def __init__(self, input_shape=768):
        self.model = None
        self.scaler = None
        self.class_weights = None

    def evaluate(self, X_test, y_test):
        """Evaluates model performance"""
        loss, accuracy, precision, recall = self.model.evaluate(X_test, y_test, verbose=0)
        '''print(f"Test Accuracy: {accuracy:.4f}")
        print(f"Test Precision: {precision:.4f}")
        print(f"Test Recall: {recall:.4f}")'''

        y_pred = self.model.predict(X_test)
        y_pred_classes = (y_pred > 0.5).astype(int)
        return y_pred_classes

    def predict_embeddings(self, embeddings):
        """Predicts vulnerability from pre-computed embeddings"""
        scaled_embeddings = self.scaler.transform(embeddings)
        predictions = self.model.predict(scaled_embeddings)
        return (predictions > 0.5).astype(int), predictions



class VulnerabilityDetectionSystem:
    """ Encapsulates the logic for the preprocessing, embeddings, training, prediction of the model
    (took as attribute)"""

    def __init__(self):
        self.preprocessor = CodePreprocessor()
        self.embedding_generator = None  # will be initialized when loading
        self.detection_model = VulnerabilityDetectionModel()


    @staticmethod
    def load(filepath):
        import joblib
        import os
        """Loads a saved system from memory        """
        system_data = joblib.load(os.path.join(filepath, 'system.joblib'))

        #new system which contains a preprocessor and the model
        system = VulnerabilityDetectionSystem()
        system.preprocessor = system_data['preprocessor']
        system.detection_model = system_data['detection_model']

        # the embedding generator
        emb_path = os.path.join(filepath, 'embedding_generator')
        system.embedding_generator = EmbeddingGenerator(emb_path)

        return system


    def predict(self, code_snippets):
        """Predicts vulnerability for new code snippets when needed"""
        clean_codes = [self.preprocessor.preprocess(code) for code in code_snippets]
        embeddings = self.embedding_generator.generate_embeddings_batch(clean_codes)
        return self.detection_model.predict_embeddings(embeddings)
