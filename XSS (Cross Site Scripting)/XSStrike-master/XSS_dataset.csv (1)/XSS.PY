import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from nltk.corpus import stopwords
from sklearn.metrics import accuracy_score, f1_score
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
import tensorflow as tf
import numpy as np
from sklearn.metrics import confusion_matrix
from tensorflow import keras
from keras.models import Model
from keras.layers import Dense
import warnings

warnings.filterwarnings('ignore')

df = pd.read_csv('E:\COLLEGE\java\XSStrike-master\XSStrike-master\XSS_dataset.csv (1)\XSS_dataset.csv', encoding='utf-8-sig')
X = df['Sentence']
y = df['Label']

import nltk

nltk.download('stopwords')

vectorizer = CountVectorizer(min_df = 2, max_df = 0.8, stop_words = stopwords.words('english'))
X = vectorizer.fit_transform(X.values.astype('U')).toarray()

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state=1)
print(X_train.shape)
print(y_train.shape)
print(X_test.shape)
print(y_test.shape)

lr_clf = LogisticRegression()
lr_clf.fit(X_train, y_train)
y_pred = lr_clf.predict(X_test)
print(f"Accuracy of Logistic Regression on test set : {accuracy_score(y_pred, y_test)}")
print(f"F1 Score of Logistic Regression on test set : {f1_score(y_pred, y_test)}")
confusion = confusion_matrix(y_test, y_pred)

TP = confusion[1, 1]
TN = confusion[0, 0]
FP = confusion[0, 1]
FN = confusion[1, 0]

sensitivity = TP / float(FN + TP)

print("sensitivity=",sensitivity)
specificity = TN / (TN + FP)
print("specificity=",specificity)


Precision = TP / float(TP + FP)
Recall = TP / float(TP + FN)
F1 = 2*((Precision*Recall)/(Precision+Recall))
print ("Precision=",Precision)

from sklearn.ensemble import AdaBoostClassifier
lr_clf = AdaBoostClassifier(n_estimators=100)
lr_clf.fit(X_train, y_train)
y_pred = lr_clf.predict(X_test)
print(f"Accuracy of AadaBoost on test set : {accuracy_score(y_pred, y_test)}")
print(f"F1 Score of AadaBoost on test set : {f1_score(y_pred, y_test)}")
confusion = confusion_matrix(y_test, y_pred)

TP = confusion[1, 1]
TN = confusion[0, 0]
FP = confusion[0, 1]
FN = confusion[1, 0]

sensitivity = TP / float(FN + TP)

print("sensitivity=",sensitivity)
specificity = TN / (TN + FP)
print("specificity=",specificity)


Precision = TP / float(TP + FP)
Recall = TP / float(TP + FN)
F1 = 2*((Precision*Recall)/(Precision+Recall))
print ("Precision=",Precision)

nb_clf = GaussianNB()
nb_clf.fit(X_train, y_train)
y_pred = nb_clf.predict(X_test)
print(f"Accuracy of Naive Bayes on test set : {accuracy_score(y_pred, y_test)}")
print(f"F1 Score of Naive Bayes on test set : {f1_score(y_pred, y_test)}")

confusion = confusion_matrix(y_test, y_pred)

TP = confusion[1, 1]
TN = confusion[0, 0]
FP = confusion[0, 1]
FN = confusion[1, 0]

sensitivity = TP / float(FN + TP)

print("sensitivity=",sensitivity)
specificity = TN / (TN + FP)
print("specificity=",specificity)


Precision = TP / float(TP + FP)
Recall = TP / float(TP + FN)
F1 = 2*((Precision*Recall)/(Precision+Recall))
print ("Precision=",Precision)

import xgboost as xgb

nb_clf = xgb.XGBClassifier(n_estimators=100)
nb_clf.fit(X_train, y_train)
y_pred = nb_clf.predict(X_test)
print(f"Accuracy of XGBoost on test set : {accuracy_score(y_pred, y_test)}")
print(f"F1 Score of XGBoost on test set : {f1_score(y_pred, y_test)}")
confusion = confusion_matrix(y_test, y_pred)

TP = confusion[1, 1]
TN = confusion[0, 0]
FP = confusion[0, 1]
FN = confusion[1, 0]

sensitivity = TP / float(FN + TP)

print("sensitivity=",sensitivity)
specificity = TN / (TN + FP)
print("specificity=",specificity)


Precision = TP / float(TP + FP)
Recall = TP / float(TP + FN)
F1 = 2*((Precision*Recall)/(Precision+Recall))
print ("Precision=",Precision)

import numpy as nm  
import matplotlib.pyplot as mtp
from sklearn.tree import DecisionTreeClassifier

nb_clf = DecisionTreeClassifier(criterion='entropy', random_state=0)
nb_clf.fit(X_train, y_train)
y_pred = nb_clf.predict(X_test)
print(f"Accuracy of Decision Tree on test set : {accuracy_score(y_pred, y_test)}")
print(f"F1 Score of Decision Tree on test set : {f1_score(y_pred, y_test)}")
confusion = confusion_matrix(y_test, y_pred)

TP = confusion[1, 1]
TN = confusion[0, 0]
FP = confusion[0, 1]
FN = confusion[1, 0]

sensitivity = TP / float(FN + TP)

print("sensitivity=",sensitivity)
specificity = TN / (TN + FP)
print("specificity=",specificity)


Precision = TP / float(TP + FP)
Recall = TP / float(TP + FN)
F1 = 2*((Precision*Recall)/(Precision+Recall))
print ("Precision=",Precision)