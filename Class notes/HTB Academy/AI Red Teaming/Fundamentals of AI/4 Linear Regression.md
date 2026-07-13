# 📈 Linear Regression

---

### What is Regression?

* **Regression = predict a continuous number.**
* Goal: estimate values (house price, temperature, visitor count).
* Difference from classification: regression = numbers, classification = categories.

---

### Linear Regression

* Assumes a **straight-line relationship** between inputs (predictors) and outputs (target).
* Goal: find the line that best fits the data by minimizing error.

---

### Simple Linear Regression

Equation:

```
y = mx + c
```

* **y:** predicted value
* **x:** predictor (input variable)
* **m:** slope (how much y changes with x)
* **c:** intercept (value of y when x = 0)
* Learned using **Ordinary Least Squares (OLS)**, which minimizes squared errors.

---

### Multiple Linear Regression

Equation:

```
y = b0 + b1x1 + b2x2 + ... + bnxn
```

* **y:** predicted value
* **x1 … xn:** predictor variables
* **b0:** intercept
* **b1 … bn:** coefficients for each predictor

---

### Ordinary Least Squares (OLS)

Steps:

1. **Residuals:** difference between actual and predicted values.
2. **Square residuals:** makes them positive, emphasizes larger errors.
3. **Sum squared residuals (RSS):** total error.
4. **Minimize RSS:** adjust coefficients until error is as small as possible.

---

### Assumptions of Linear Regression

* **Linearity:** relationship between features & target is linear.
* **Independence:** each observation is independent.
* **Homoscedasticity:** error variance is consistent across predictions.
* **Normality:** errors follow a normal distribution.

If these assumptions fail → predictions may be unreliable.

---

👉 **Memory Hook:**
Linear regression = “draw the best straight line through the cloud of points.”


