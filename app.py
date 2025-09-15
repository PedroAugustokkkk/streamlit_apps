import streamlit as st
from calculadora import soma, subtracao, multiplicacao, divisao

st.title("Calculadora com Streamlit")

num1 = st.number_input("Digite o primeiro número", value=0.0)
num2 = st.number_input("Digite o segundo número", value=0.0)

col1, col2, col3, col4 = st.columns(4)

resultado = None

with col1:
    if st.button("Somar"):
        resultado = soma(num1, num2)

with col2:
    if st.button("Subtrair"):
        resultado = subtracao(num1, num2)

with col3:
    if st.button("Multiplicar"):
        resultado = multiplicacao(num1, num2)

with col4:
    if st.button("Dividir"):
        resultado = divisao(num1, num2)

# Exiba o resultado
if resultado is not None:
    st.success(f"O resultado é: {resultado}")