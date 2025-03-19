FROM nginx:alpine

# Remover arquivos padrão do NGINX (opcional)
RUN rm -rf /usr/share/nginx/html/*

# Copiar os arquivos do projeto para a pasta correta
COPY . /usr/share/nginx/html

# Definir diretório de trabalho
WORKDIR /usr/share/nginx/html

# Expor a porta 80 para o container
EXPOSE 80

# Comando de execução do NGINX
CMD ["nginx", "-g", "daemon off;"]
