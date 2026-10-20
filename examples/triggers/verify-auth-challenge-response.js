// VerifyAuthChallengeResponse: callback style, to show both handler styles work.
exports.handler = (event, _context, callback) => {
  const expected = event.request.privateChallengeParameters.answer;
  event.response.answerCorrect = event.request.challengeAnswer === expected;
  callback(null, event);
};
