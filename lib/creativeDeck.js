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

function riskLevel(random) {
  const value = random();
  if (value < 0.15) return "wildcard";
  if (value < 0.40) return "experimental";
  return "accessible";
}

export function buildCreativeDeck(seed, count = 8) {
  const random = seededRandom(seed);
  const recipes = [];
  for (let index = 0; index < count; index += 1) {
    const recent = recipes.slice(-3);
    recipes.push({
      slot: index + 1,
      mechanism: draw(CREATIVE_DECK.mechanism, random, recent.map((item) => item.mechanism)),
      visual_world: draw(CREATIVE_DECK.visual_world, random, recent.map((item) => item.visual_world)),
      copy_voice: draw(CREATIVE_DECK.copy_voice, random, recent.map((item) => item.copy_voice)),
      footage_strategy: draw(CREATIVE_DECK.footage_strategy, random, recent.map((item) => item.footage_strategy)),
      typography: draw(CREATIVE_DECK.typography, random, recent.map((item) => item.typography)),
      risk_level: riskLevel(random),
      serendipity_words: [
        draw(SERENDIPITY_WORDS, random),
        draw(SERENDIPITY_WORDS, random),
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

