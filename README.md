# Discord Link Moderator
> This bot is designed to test links send against [Virus Total](https://www.virustotal.com) virus tester.

## Requirements

1. Discord Bot Token **[Guide](https://discordjs.guide/preparations/setting-up-a-bot-application.html#creating-your-bot)**  
2. Virus Total API Key **See Below for guide.**   
3. Node.js  
## Virus Total API Key Guide  

1- Create a Virus Total Account [Click Here](https://www.virustotal.com/gui/join-us)  
2- Once signed in/up click your profile and click `API Key`   
![Profile](https://files.readme.io/73a8178-Screen_Shot_2019-10-16_at_3.51.46_PM.png)  
3- Copy your API Key into the config.json  
![Image](https://files.readme.io/6b36a65-firefox_qYVnsybuxR.png)   


## 🚀 Getting Started 

```
git clone https://github.com/ARR4NN/Discord-Link-Moderation
cd Discord-Link-Moderation
npm install
```

After installation finishes you can use `node index.js` to start the bot.

## ⚙️ Configuration

Copy or Rename `config.json.example` to `config.json` and fill out the values:

⚠️ **Note: Never commit or share your token or api keys publicly** ⚠️

```json
{
  "TOKEN": "",
  "VIRUS_TOTAL_API_KEY": ""
}
```

## 📝 Features

* 🔎 Check all links and store other known bad links to reduce stress on the API.

## 🤝 Contributing

1. [Fork the repository](https://github.com/ARR4NN/Discord-Link-Moderation/fork)
2. Clone your fork: `git clone https://github.com/your-username/Discord-Link-Moderation.git`
3. Create your feature branch: `git checkout -b my-new-feature`
4. Commit your changes: `git commit -am 'Add some feature'`
5. Push to the branch: `git push origin my-new-feature`
6. Submit a pull request

## 📝 Credits

× [Virus Total](https://www.virustotal.com) - Used to check links.  
× [Discord JS](https://discord.js.org/#/) - Language used for coding.  
× [Virus Total API Package](https://www.npmjs.com/package/virustotal-api) - Made this project much cleaner.  
