# docker build -t unibz2025-agile-final-project-fe .
# docker run -p 3000:80 unibz2025-agile-final-project-fe


# ---- Step 1: Build the Vite React app ----
FROM node:18-alpine AS build

WORKDIR /app

# Copy dependencies files first (better caching)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy all project files
COPY . .

# Build for production (outputs to /dist)
RUN npm run build


# ---- Step 2: Serve static files using Nginx ----
FROM nginx:stable-alpine

# Remove default Nginx static files
RUN rm -rf /usr/share/nginx/html/*

# Copy Vite build output to Nginx
COPY --from=build /app/dist /usr/share/nginx/html

# Expose port 80 for incoming requests
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
