# 🧑‍🏫 Supervised Learning Algorithms 

---

### What It Is

* Supervised learning = teaching with an **answer key**.
* You give the algorithm examples (features) **with labels** (correct answers).
* It learns the mapping: **inputs → outputs**, then applies it to unseen data.

---

### Two Main Problem Types

* **Classification:** predict a category (spam/not spam, cat/dog).
* **Regression:** predict a number (house price, stock value).

---

### Core Concepts

* **Training Data:** labeled dataset (features + labels). Quality and quantity affect accuracy.
* **Features:** measurable properties used for input (e.g., size, bedrooms, location for houses).
* **Labels:** the correct outcome (e.g., actual house price).
* **Model:** function that maps features → labels, learned from data.
* **Training:** adjusting model parameters to minimize prediction error.
* **Prediction:** using the trained model to predict labels for new data.
* **Inference:** broader than prediction; explains structure and relationships in data.

---

### Evaluation Metrics

* **Accuracy:** % of correct predictions.
* **Precision:** % of predicted positives that were correct.
* **Recall:** % of actual positives that were correctly identified.
* **F1-score:** balance of precision and recall.

---

### Generalization

* A good model can handle **new, unseen data** (not just the training set).

---

### Common Issues

* **Overfitting:** memorizes training data, fails on new data.
* **Underfitting:** too simple to capture real patterns → bad on training & new data.

---

### Techniques to Improve

* **Cross-Validation:** split data into folds, test on different subsets. Helps check generalization.
* **Regularization:** add penalty for complexity to avoid overfitting.

  * **L1:** pushes some weights to zero → selects features.
  * **L2:** shrinks weights evenly → smoother model.

---

👉 **Memory Hook:**
Supervised = “answer key.”
Classification = categories.
Regression = numbers.
Overfit = memorized.
Underfit = oversimplified.

