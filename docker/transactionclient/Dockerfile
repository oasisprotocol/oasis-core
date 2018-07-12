FROM node:8

WORKDIR /usr/src/app

# Install app dependencies
COPY ethereum/package*.json ./
RUN npm install

# Copy app source
COPY ethereum/test/web3.js ./

EXPOSE 3000
ENTRYPOINT [ "node", "web3.js" ]
# First argument is the web3 gateway for txns.
# Second argument is the rate at which tnx will be sent.
# Optional third argument is a remote prometheus pushgateway.
CMD [ "http://localhost:9454", "1000" ]
