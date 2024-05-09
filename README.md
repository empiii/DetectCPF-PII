## Detector de CPFs no Burp Suite

Este script foi escrito em Python e é uma extensão para o Burp Suite que detecta a presença de CPFs (Cadastro de Pessoas Físicas) em respostas HTTP. Ele foi projetado para auxiliar na identificação de possíveis vazamentos de informações pessoais sensíveis durante Pentestes web.

### Funcionalidades Principais

- **Detectar CPFs em Respostas HTTP:** A extensão utiliza expressões regulares para buscar padrões de CPFs em respostas HTTP.
- **Interface Gráfica Simples:** Uma simples interface gráfica é fornecida para ativar ou desativar a detecção de CPFs.

### Instalação

1. **Download Jython Standalone 2.7.3:**
   - Faça o download do [Jython Standalone 2.7.3](https://www.jython.org/download)

2. **Configurar o Apontamento Jython:**
   - Configure o apontamento para o Jython em `Settings > Extensions > Python environment Location`

3. **Download do Código:**
   - Faça o download do arquivo `piicpf.py`

4. **Adicionar a Extensão no Burp Suite:**
   - Adicione a extensão dentro do Burp Suite em `Burp Extensions`

5. **Configurar a Extensão:**
   - Em `Extension Details > Extension Type`, selecione Python e selecione o arquivo da extensão

6. **Ativar a Extensão:**
   - Certifique-se de que a extensão esteja ativada.

### Como Usar

1. **Ativar a Detecção de CPFs:**
   - Na interface gráfica da extensão, marque a opção "Detect CPFs" para ativar a detecção.

2. **Executar Testes:**
   - Durante os testes no Burp Suite, a extensão passivamente analisará as respostas HTTP em busca de CPFs.

3. **Visualizar Resultados:**
   - Se um CPF for encontrado, um alerta será gerado no Burp Suite, indicando a presença do CPF na resposta HTTP.

### Classes Principais

- **BurpExtender:** Classe principal que implementa as interfaces `IBurpExtender`, `IScannerCheck` e `ITab`. Registra a extensão no Burp Suite, define a lógica de detecção de CPFs e configura a interface gráfica.
- **CustomScanIssue:** Implementa a interface `IScanIssue` e representa um problema de segurança detectado pela extensão, como a presença de um CPF em uma resposta HTTP.

### Considerações sobre o Código

- A extensão utiliza expressões regulares para buscar padrões de CPFs em respostas HTTP.
- A detecção de CPFs é realizada passivamente durante os testes, sem alterar o comportamento normal da aplicação.
- A interface gráfica simples permite ao usuário configurar facilmente a extensão.

Esta documentação fornece uma visão geral do funcionamento da extensão e como ela pode ser usada para identificar CPFs em respostas HTTP durante testes de segurança em aplicações web.

# Resultado. 

https://github.com/empiii/DetectCPF-PII/assets/47393806/dd536d8c-eb78-4bd7-be38-d794fd1bd007




