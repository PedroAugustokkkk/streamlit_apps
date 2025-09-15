import time
def soma(a, b):
    '''
    Função com dois args para realizar a uma soma
    Ex.: 1, 2 -> 3
    4, 6 -> 10
    '''
    return a + b

def subtracao(a, b):
    '''
    Função com dois args para realizar uma subtração
    Ex.: 2, 1 -> 1
    1, 2 -> -1
    '''
    return a - b

def multiplicacao(a, b):
    '''
    Função com dois args para realizar uma multiplicação
    Ex.: 2, 2 -> 4
    3, 9 -> 27
    '''
    return a * b

def divisao(a, b):
    '''
    Função com dois args para realizar uma divisão
    Ex.: 2, 2 -> 1
    6, 3 -> 2
    '''
    if b == 0:
        return "Erro: divisão por zero!"
    return a / b

def obter_numero(prompt):
    '''
    Função para pedir o número que as outras funções utilizaram
    para realizar as operações.
    '''
    while True:
        try:
            valor = float(input(prompt))
            return valor
        except ValueError:
            print("Entrada inválida! Digite um número válido.")

def menu():
    '''
    Função para exibir o menu completo ao usuário.
    '''
    print("\n=== Calculadora Simples ===")
    print("1 - Soma")
    print("2 - Subtração")
    print("3 - Multiplicação")
    print("4 - Divisão")
    print("0 - Sair")

if __name__ == '__main__':
    while True:
        time.sleep(3)
        menu() 
        escolha = input("Escolha uma opção: ").strip()
        
        if escolha == "0":
            print("Saindo da calculadora. Até mais!")
            break
        elif escolha in ["1", "2", "3", "4"]:
            num1 = obter_numero("Digite o primeiro número: ")
            num2 = obter_numero("Digite o segundo número: ")

            if escolha == "1":
                resultado = soma(num1, num2)
            elif escolha == "2":
                resultado = subtracao(num1, num2)
            elif escolha == "3":
                resultado = multiplicacao(num1, num2)
            elif escolha == "4":
                resultado = divisao(num1, num2)
            
            print(f"Resultado: {resultado}")
        else:
            print("Opção inválida! Escolha uma opção do menu.")
