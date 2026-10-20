// DefineAuthChallenge: one custom challenge per sign-in, three attempts.
const MAX_ATTEMPTS = 3;

exports.handler = async (event) => {
  const session = event.request.session ?? [];
  const last = session[session.length - 1];

  if (event.request.userNotFound) {
    event.response.issueTokens = false;
    event.response.failAuthentication = true;
  } else if (last?.challengeName === "CUSTOM_CHALLENGE" && last.challengeResult) {
    event.response.issueTokens = true;
    event.response.failAuthentication = false;
  } else if (session.length >= MAX_ATTEMPTS) {
    event.response.issueTokens = false;
    event.response.failAuthentication = true;
  } else {
    event.response.issueTokens = false;
    event.response.failAuthentication = false;
    event.response.challengeName = "CUSTOM_CHALLENGE";
  }
  return event;
};
