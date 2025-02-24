const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');

const {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
} = require('@aws-sdk/lib-dynamodb');

const express = require('express');
const serverless = require('serverless-http');

const app = express();

const USERS_TABLE = process.env.USERS_TABLE;
const client = new DynamoDBClient();
const docClient = DynamoDBDocumentClient.from(client);
const bcrypt = require('bcryptjs');
const saltRounds = 10;
const salt = bcrypt.genSaltSync(saltRounds);
const jwt = require('jsonwebtoken');

app.use(express.json());

app.get('/users/:id', async (req, res) => {
  const params = {
    TableName: USERS_TABLE,
    Key: {
      id: req.params.id,
    },
  };

  try {
    const command = new GetCommand(params);
    const { Item } = await docClient.send(command);
    if (Item) {
      res.json({ ...Item });
    } else {
      res
        .status(404)
        .json({ error: 'Could not find user with provided "userId"' });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: 'Could not retrieve user' });
  }
});

app.post('/users', async (req, res) => {
  const { email, username, password } = req.body;
  try {
    if (typeof username !== 'string') {
      res.status(400).json({ error: '"username" must be a string' });
    } else if (typeof password !== 'string') {
      res.status(400).json({ error: '"password" must be a string' });
    } else if (typeof email !== 'string') {
      res.status(400).json({ error: '"email" must be a string' });
    }
    const hashedPassword = await bcrypt.hashSync(password, salt);

    const params = {
      TableName: USERS_TABLE,
      Item: {
        id: email,
        account_type: 'free_tier',
        username,
        password: hashedPassword,
      },
      ConditionExpression: 'attribute_not_exists(id)',
    };

    const command = new PutCommand(params);
    await docClient.send(command);
    res.json({ ...params.Item });
  } catch (error) {
    console.log('error: ', error, 'error.code:', error.message);
    if (error.message === 'ConditionalCheckFailedException: The conditional request failed' || JSON.stringify(error).search('ConditionalCheckFailedException') != -1) {
      res.status(422).json({ error: 'Username Already Taken' });
      return;
    }
    res.status(500).json({ error: 'Could not create user' });
    return;
  }
});

app.post('/users/login', async (req, res) => {
  const { username, pass } = req.body;
  if (typeof username !== 'string') {
    res.status(400).json({ error: '"username" must be a string' });
  } else if (typeof pass !== 'string') {
    res.status(400).json({ error: '"pass" must be a string' });
  }

  const params = {
    TableName: USERS_TABLE,
    Key: {
      username: username,
    },
  };

  try {
    const command = new GetCommand(params);
    const { Item } = await docClient.send(command);
    console.log('Item: ', Item);

    if (Item) {
      // check the pass matches the bcrypted pass
      const match = await bcrypt.compare(pass, Item.password);
      if (!match) {
        console.log('passwords not matching');
        res.status(404).json({
          error: 'Could not find user with provided "username", and "password"',
        });
      } else {
        const token = jwt.sign(
          {
            data: { id: Item.id, username: Item.username },
          },
          process.env.JWT_SECRET,
          { expiresIn: 86400 * 30 }
        );
        return res.status(200).json({
          data: {
            message: 'successfully Logged In',
            token,
            username,
          },
        });
      }
    } else {
      res
        .status(404)
        .json({ error: 'Could not find user with provided "username"' });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: 'Could not retrieve user' });
  }
});

app.use((req, res, next) => {
  return res.status(404).json({
    error: 'Not Found',
  });
});

exports.handler = serverless(app);
