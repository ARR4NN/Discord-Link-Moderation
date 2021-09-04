
/**
 * Module Imports
 */
const { Client, Collection, Intents } = require("discord.js");
const Discord = require("discord.js");
const fs = require("fs/promises")
const { TOKEN, VIRUS_TOTAL_API_KEY } = require("./json/config.json")
const client = new Client({
    disableMentions: "everyone",
    restTimeOffset: 0,
    intents: [
        Intents.FLAGS.GUILDS,
        Intents.FLAGS.GUILD_MEMBERS,
        Intents.FLAGS.GUILD_MESSAGES,
        Intents.FLAGS.GUILD_VOICE_STATES,
    ],
    partials: ['MESSAGE', 'CHANNEL', 'REACTION'],
});
const VirusTotalApi = require("virustotal-api");
const virusTotal = new VirusTotalApi(VIRUS_TOTAL_API_KEY);
client.login(TOKEN);
client.on("ready", function () {
    console.log(`Bot has started`);
    client.user.setActivity("Your Links", { type: 3 });;
});
client.on("messageCreate", function (message) {
    const regex = /((([A-Za-z]{3,9}:(?:\/\/)?)(?:[\-;:&=\+\$,\w]+@)?[A-Za-z0-9\.\-]+|(?:www\.|[\-;:&=\+\$,\w]+@)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-_]*)?\??(?:[\-\+=&;%@\.\w_]*)#?(?:[\.\!\/\\\w]*))?)/
    const test = regex.test(message.content)
    if (test) {
        const badlinksraw = require("./json/badlinks.json")
        const safelinksraw = require("./json/trusted.json")
        const linkmessageraw = regex.exec(message.content)
        const linkmessage = linkmessageraw[0]
        const hostname = linkmessageraw[2]
        const badlinks = badlinksraw
        if (safelinksraw.includes(hostname)) {
            message.react("✅")
            return
        }
        if (badlinks.includes(hostname)) {
            message.delete()
            const embed = new Discord.MessageEmbed()
                .setColor("WHITE")
                .setTitle("Message Deleted")
                .addField("Author", message.author.toString(), true)
                .addField("Reason", "Malicious link detected", true)
            message.channel.send({ embeds: [embed] })
            return
        }
        virusTotal
            .urlScan(linkmessage)
            .then(response => {
                let resource = response.resource;
                virusTotal.urlReport(resource).then(result => {
                    if (result.positives >= 5) {
                        badlinksraw.push(hostname)
                        fs.writeFile("json/badlinks.json", JSON.stringify(badlinksraw), (err) => { });
                        message.delete()
                        const embed = new Discord.MessageEmbed()
                            .setColor("WHITE")
                            .setTitle("Message Deleted")
                            .addField("Author", message.author.toString(), true)
                            .addField("Reason", "Malicious link detected", true)
                        message.channel.send({ embeds: [embed] })
                    } else {
                        message.react("✅")
                    }
                });
            })
    }
});
process.on("unhandledRejection", async (error) => {
    console.log(error)
})
process.on("unhandledException", async (error) => {
    console.log(error)
})