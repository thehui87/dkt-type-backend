mkdir dkt-type-backend

cd dkt-type-backend

npm init -y

npm install typescript ts-node @types/node --save-dev

npx tsc --init

npm install express mongoose bcryptjs jsonwebtoken

npm install @types/express @types/mongoose @types/bcryptjs @types/jsonwebtoken --save-dev

npm install dotenv

npm install @types/dotenv --save-dev
