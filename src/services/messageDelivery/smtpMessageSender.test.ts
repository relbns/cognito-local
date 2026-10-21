import net from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { TestContext } from "../../__tests__/testContext";
import * as TDB from "../../__tests__/testDataBuilder";
import { SmtpMessageSender } from "./smtpMessageSender";

interface ReceivedMail {
  from: string;
  to: string[];
  data: string;
}

const decodeQuotedPrintable = (raw: string) =>
  raw
    .replace(/=\r\n/g, "")
    .replace(/=([0-9A-F]{2})/g, (_, hex) =>
      String.fromCharCode(Number.parseInt(hex, 16)),
    );

const startSmtpServer = async () => {
  const received: ReceivedMail[] = [];
  const server = net.createServer((socket) => {
    let buffer = "";
    let inData = false;
    let mail: ReceivedMail = { from: "", to: [], data: "" };
    const reply = (line: string) => socket.write(`${line}\r\n`);
    reply("220 localhost ESMTP test");
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      while (true) {
        if (inData) {
          const end = buffer.indexOf("\r\n.\r\n");
          if (end < 0) return;
          mail.data = buffer.slice(0, end);
          buffer = buffer.slice(end + 5);
          inData = false;
          received.push(mail);
          mail = { from: "", to: [], data: "" };
          reply("250 OK queued");
          continue;
        }
        const eol = buffer.indexOf("\r\n");
        if (eol < 0) return;
        const line = buffer.slice(0, eol);
        buffer = buffer.slice(eol + 2);
        const verb = line.slice(0, 4).toUpperCase();
        if (verb === "EHLO" || verb === "HELO") {
          reply("250 localhost");
        } else if (verb === "MAIL") {
          mail.from = line.replace(/^MAIL FROM:\s*<([^>]*)>.*$/i, "$1");
          reply("250 OK");
        } else if (verb === "RCPT") {
          mail.to.push(line.replace(/^RCPT TO:\s*<([^>]*)>.*$/i, "$1"));
          reply("250 OK");
        } else if (verb === "DATA") {
          inData = true;
          reply("354 End data with <CR><LF>.<CR><LF>");
        } else if (verb === "QUIT") {
          reply("221 Bye");
          socket.end();
        } else {
          reply("250 OK");
        }
      }
    });
  });
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve()),
  );
  const { port } = server.address() as net.AddressInfo;
  return {
    port,
    received,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
};

describe("SmtpMessageSender", () => {
  let smtp: Awaited<ReturnType<typeof startSmtpServer>>;
  let sender: SmtpMessageSender;

  beforeEach(async () => {
    smtp = await startSmtpServer();
    sender = new SmtpMessageSender("127.0.0.1", smtp.port);
  });

  afterEach(async () => {
    await smtp.close();
  });

  it("emails the custom subject and message to the destination", async () => {
    await sender.sendEmail(
      TestContext,
      TDB.user({ Username: "jane" }),
      "jane@example.test",
      {
        __code: "123456",
        emailSubject: "Welcome to Example",
        emailMessage: "Your code is 123456",
      },
    );

    expect(smtp.received).toHaveLength(1);
    const [mail] = smtp.received;
    const data = decodeQuotedPrintable(mail.data);
    expect(mail.from).toBe("noreply@cognito.local");
    expect(mail.to).toEqual(["jane@example.test"]);
    expect(data).toMatch(/^Subject: Welcome to Example$/m);
    expect(data).toContain("Your code is 123456");
    expect(data).toContain("User: jane");
  });

  it("uses a default subject and a code message when none is customised", async () => {
    await sender.sendEmail(TestContext, TDB.user(), "user@example.test", {
      __code: "654321",
    });

    const data = decodeQuotedPrintable(smtp.received[0].data);
    expect(data).toMatch(/^Subject: Cognito Verification$/m);
    expect(data).toContain("Your verification code is: 654321");
  });

  it("escapes the username and the message in the HTML part", async () => {
    await sender.sendEmail(
      TestContext,
      TDB.user({ Username: "<script>x</script>" }),
      "user@example.test",
      { __code: "111111", emailMessage: 'Click <a href="x">here</a>' },
    );

    const data = decodeQuotedPrintable(smtp.received[0].data);
    expect(data).toContain("User: &lt;script&gt;x&lt;/script&gt;");
    expect(data).toContain("Click &lt;a href=&quot;x&quot;&gt;here&lt;/a&gt;");
    expect(data).not.toContain("<script>");
  });

  it("routes an SMS as an email to <number>@sms.local", async () => {
    await sender.sendSms(TestContext, TDB.user(), "+15555550100", {
      __code: "222222",
      smsMessage: "Your sign-in code is 222222",
    });

    const [mail] = smtp.received;
    const data = decodeQuotedPrintable(mail.data);
    expect(mail.from).toBe("sms@cognito.local");
    expect(mail.to).toEqual(["+15555550100@sms.local"]);
    expect(data).toMatch(/^Subject: SMS to \+15555550100$/m);
    expect(data).toContain("Your sign-in code is 222222");
  });

  it("sends the code when the SMS has no custom message", async () => {
    await sender.sendSms(TestContext, TDB.user(), "+15555550100", {
      __code: "333333",
    });

    expect(decodeQuotedPrintable(smtp.received[0].data)).toContain(
      "Your verification code is: 333333",
    );
  });

  it("fails when the SMTP server cannot be reached", async () => {
    await smtp.close();

    await expect(
      sender.sendEmail(TestContext, TDB.user(), "user@example.test", {
        __code: "444444",
      }),
    ).rejects.toThrow();
  });
});
