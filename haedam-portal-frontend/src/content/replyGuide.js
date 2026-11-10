// A writing aid, never a statement that an inspection or action took place.
export const REPLY_PROMPTS = [
  "[확인한 내용 입력]",
  "[실제 조치와 결과 입력]",
  "[추가 안내 또는 해당 없음 입력]",
];

export const REPLY_OUTLINE = `1. 확인한 내용
${REPLY_PROMPTS[0]}

2. 조치 및 결과
${REPLY_PROMPTS[1]}

3. 추가 안내
${REPLY_PROMPTS[2]}`;

export const hasReplyPrompts = (reply) =>
  REPLY_PROMPTS.some((prompt) => reply.includes(prompt));
