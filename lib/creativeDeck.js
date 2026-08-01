import { createHash } from "crypto";

const CREATIVE_DECK = {
  mechanism: [
    "absurd everyday observation",
    "visual metaphor",
    "deadpan object joke",
    "tiny human micro-story",
    "false documentary",
    "unexpected comparison",
    "POV discovery",
    "before-and-after transformation",
    "visual contradiction",
    "sensory mood fragment",
    "anti-ad",
    "found-footage moment",
    "pattern interruption",
    "one-line mystery",
    "mundane object mythology",
    "playful pseudo-science",
  ],
  visual_world: [
    "ordinary life made slightly strange",
    "soft cinematic realism",
    "lo-fi phone footage",
    "retro-futurist",
    "nighttime neon",
    "bright domestic daylight",
    "macro and texture",
    "quiet architecture",
    "abstract light and reflections",
    "awkward everyday comedy",
    "dreamlike landscape",
    "surveillance-camera energy",
    "editorial minimalism",
    "colorful visual overload",
    "rainy urban atmosphere",
    "unexpected food imagery",
  ],
  copy_voice: [
    "dry deadpan",
    "playfully confrontational",
    "poetic but plain",
    "mysterious",
    "warmly observant",
    "pseudo-scientific",
    "internet-native",
    "understated absurdity",
    "confidently direct",
    "romantic",
    "slightly uncanny",
    "self-aware anti-ad",
  ],
  footage_strategy: [
    "one unmistakable moving subject",
    "camera movement through a place",
    "unusual object close-up",
    "human reaction without headphones",
    "macro texture in motion",
    "wide environment with negative space",
    "handheld POV action",
    "repeating mechanical movement",
    "light, shadow or reflection as subject",
    "deliberately static tableau",
    "two-shot visual contrast",
    "found moment with imperfect framing",
  ],
  typography: [
    "bold centered statement",
    "deadpan subtitle",
    "editorial top lockup",
    "two-beat kinetic reveal",
    "minimal object label",
    "oversized single phrase",
    "small mysterious caption",
    "asymmetric magazine layout",
  ],
};

const RELIABLE_MECHANISMS = [
  "tiny human micro-story",
  "POV discovery",
  "before-and-after transformation",
  "sensory mood fragment",
  "found-footage moment",
  "plain emotional portrait",
  "recognizable listening moment",
];

const CREATIVE_MECHANISMS = [
  "visual metaphor",
  "unexpected comparison",
  "visual contradiction",
  "pattern interruption",
  "one-line mystery",
  "anti-ad",
  "awkward everyday observation",
];

const RELIABLE_VISUAL_WORLDS = [
  "soft cinematic realism",
  "lo-fi phone footage",
  "nighttime neon",
  "bright domestic daylight",
  "quiet architecture",
  "rainy urban atmosphere",
  "editorial minimalism",
];

const RELIABLE_COPY_VOICES = [
  "confidently direct",
  "warmly observant",
  "poetic but plain",
  "internet-native but natural",
  "emotionally honest",
];

const SERENDIPITY_WORDS = [
  "jellyfish", "laundromat", "magnets", "pigeon", "chrome", "motel", "toaster",
  "aquarium", "escalator", "balloon", "supermarket", "fog", "plastic", "satellite",
  "mushroom", "carwash", "mirror", "cake", "elevator", "antenna", "receipt",
  "bubbles", "fluorescent", "parking", "vacuum", "arcade", "snow", "ceramic",
  "conveyor", "insects", "clouds", "scanner", "fruit", "mannequin", "sprinkler",
  "tunnel", "glitter", "microscope", "traffic", "curtain", "fish", "machine",
];

const SERENDIPITY_MODIFIERS = [
  "strange", "dreamy", "awkward", "hypnotic", "surreal", "lonely", "funny",
  "glowing", "slow motion", "close up", "at night", "retro", "abstract",
  "unexpected", "colorful", "cinematic", "handheld", "macro",
];

const HOOK_STRUCTURES = [
  "direct benefit",
  "plain observation",
  "specific mood statement",
  "simple invitation",
  "question",
  "POV",
  "compact contrast",
  "quoted dialogue",
  "mini plot twist",
  "deadpan documentary caption",
  "object label",
  "imperative",
];

const HOOK_STRUCTURES_BY_TONE = {
  accessible: [
    "direct benefit",
    "plain observation",
    "specific mood statement",
    "simple invitation",
    "question",
    "POV",
    "compact contrast",
    "imperative",
  ],
  creative: [
    "quoted dialogue",
    "mini plot twist",
    "deadpan documentary caption",
    "object label",
    "question",
    "POV",
    "compact contrast",
  ],
  wildcard: HOOK_STRUCTURES,
};

const BATCH_TONE_PROFILES = [
  ["accessible", "accessible", "accessible", "accessible", "accessible", "creative", "creative", "wildcard"],
  ["accessible", "accessible", "accessible", "accessible", "accessible", "creative", "creative", "wildcard"],
  ["accessible", "accessible", "accessible", "accessible", "accessible", "accessible", "creative", "wildcard"],
  ["accessible", "accessible", "accessible", "accessible", "creative", "creative", "creative", "wildcard"],
];

const HOOK_FOCUS_BY_TONE = {
  accessible: ["audience story", "emotional truth", "playlist benefit", "listening moment", "identity", "invitation"],
  creative: ["audience story", "emotional truth", "playlist benefit", "identity", "creative contrast"],
  wildcard: ["wildcard", "scene-led", "creative contrast"],
};

function seededRandom(seed) {
  let state = Number.parseInt(createHash("sha256").update(String(seed)).digest("hex").slice(0, 8), 16) || 1;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

function draw(pool, random, recent = []) {
  const fresh = pool.filter((item) => !recent.includes(item));
  const choices = fresh.length ? fresh : pool;
  return choices[Math.floor(random() * choices.length)];
}

function shuffle(values, random) {
  const copy = [...values];
  for (let index = copy.length - 1; index > 0; index -= 1) {
    const target = Math.floor(random() * (index + 1));
    [copy[index], copy[target]] = [copy[target], copy[index]];
  }
  return copy;
}

export function buildCreativeDeck(seed, count = 8) {
  const random = seededRandom(seed);
  const toneProfile = draw(BATCH_TONE_PROFILES, random);
  const requestedTones = Array.from({ length: count }, (_, index) => toneProfile[index % toneProfile.length]);
  const wildcardCount = Math.max(1, requestedTones.filter((tone) => tone === "wildcard").length);
  const nonWildcardTones = shuffle(requestedTones.filter((tone) => tone !== "wildcard"), random);
  const toneMix = [...nonWildcardTones.slice(0, Math.max(0, count - wildcardCount)), ...Array(wildcardCount).fill("wildcard")].slice(0, count);
  const usedHookStructures = new Set();
  const creativeSlots = toneMix.map((tone, index) => tone !== "accessible" ? index + 1 : null).filter(Boolean);
  const lateralSearchCount = Math.min(creativeSlots.length, 1 + Math.floor(random() * 2));
  const lateralSearchSlots = new Set(shuffle(creativeSlots, random).slice(0, lateralSearchCount));
  const recipes = [];
  for (let index = 0; index < count; index += 1) {
    const recent = recipes.slice(-3);
    const firstSerendipityWord = draw(SERENDIPITY_WORDS, random);
    const risk = toneMix[index];
    const structurePool = HOOK_STRUCTURES_BY_TONE[risk] || HOOK_STRUCTURES;
    const availableStructures = structurePool.filter((item) => !usedHookStructures.has(item));
    const hookStructure = draw(availableStructures.length ? availableStructures : structurePool, random);
    usedHookStructures.add(hookStructure);
    const mechanismPool = risk === "accessible" ? RELIABLE_MECHANISMS : risk === "creative" ? CREATIVE_MECHANISMS : CREATIVE_DECK.mechanism;
    const visualWorldPool = risk === "accessible" ? RELIABLE_VISUAL_WORLDS : CREATIVE_DECK.visual_world;
    const copyVoicePool = risk === "accessible" ? RELIABLE_COPY_VOICES : CREATIVE_DECK.copy_voice;
    const hookFocus = draw(HOOK_FOCUS_BY_TONE[risk] || HOOK_FOCUS_BY_TONE.accessible, random, recent.map((item) => item.hook_focus));
    recipes.push({
      slot: index + 1,
      mode: risk === "accessible" ? "reliable" : risk,
      mechanism: draw(mechanismPool, random, recent.map((item) => item.mechanism)),
      visual_world: draw(visualWorldPool, random, recent.map((item) => item.visual_world)),
      copy_voice: draw(copyVoicePool, random, recent.map((item) => item.copy_voice)),
      hook_structure: hookStructure,
      hook_focus: hookFocus,
      footage_strategy: draw(CREATIVE_DECK.footage_strategy, random, recent.map((item) => item.footage_strategy)),
      typography: draw(CREATIVE_DECK.typography, random, recent.map((item) => item.typography)),
      risk_level: risk,
      workflow: "concept_first",
      visual_role: lateralSearchSlots.has(index + 1) ? "lateral_support" : "direct_support",
      lateral_search: lateralSearchSlots.has(index + 1),
      serendipity_words: [
        firstSerendipityWord,
        draw(SERENDIPITY_WORDS, random, [firstSerendipityWord]),
      ],
      serendipity_modifier: draw(SERENDIPITY_MODIFIERS, random),
    });
  }
  return { seed: String(seed), recipes };
}

export function serendipityPexelsQuery(recipe = {}, seed = "") {
  const random = seededRandom(`${seed}:${recipe.slot || 0}:${recipe.serendipity_words?.join(":") || ""}`);
  const words = Array.isArray(recipe.serendipity_words) && recipe.serendipity_words.length
    ? recipe.serendipity_words
    : [draw(SERENDIPITY_WORDS, random), draw(SERENDIPITY_WORDS, random)];
  const word = words[Math.floor(random() * words.length)];
  const modifier = recipe.serendipity_modifier || draw(SERENDIPITY_MODIFIERS, random);
  return `${modifier} ${word}`.replace(/\s+/g, " ").trim().slice(0, 120);
}
