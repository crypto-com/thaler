//! cryptocurrency cat logo and jok
use rand::Rng;

fn wants_emoji() -> bool {
    cfg!(target_os = "macos")
}

#[derive(Copy, Clone)]
struct Emoji<'a, 'b>(pub &'a str, pub &'b str);

impl<'a, 'b> Emoji<'a, 'b> {
    pub fn new(emoji: &'a str, fallback: &'b str) -> Emoji<'a, 'b> {
        Emoji(emoji, fallback)
    }
}

impl<'a, 'b> std::fmt::Display for Emoji<'a, 'b> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if wants_emoji() {
            write!(f, "{}", self.0)
        } else {
            write!(f, "{}", self.1)
        }
    }
}

/// return the cryptocurrency cat logo
pub fn get_logo() -> String {
    r#"
                                   8N 8NNND$ 8N
                              7DDNI           ZDN
                           NNO                   $D
                          N                        D
                        MN                ?DD    OND
                       NN                          N7
                      NM                           D
                     NN               N          ND
                    ND                 NN8  DNDNZ
                  ZN                     NN
                 NN                      N
              NNO                       N
           8NN                          N
      DNNN                              M8
  ND             7NN    D$               D?
  N         ?NNN    ZN   8N$              DN
    DNNN DNNN          N    ZNNNI           NN
                        N      N   INDN       NM
                        8M     N        8N8     D7
                         N    N7           ON     ?D
                        N7   MD               DN      8N
                    ONNO    N                    NNO  NO
                   $M    ?NZ
                     M?N
    "#
    .into()
}

/// returns a jok
pub fn get_jok() -> String {
    let joks = vec![
        ("If you think I talk too much, let me know. We can talk about it", "😷"),
        ("No bees no honey .... No work no money", "🐝"),
        ("My bed is more comfortable in the morning thank it is at night", "🛌"),
        ("I asked God for a bike, but I know God doesn’t work that way.\n So I stole a bike and asked for forgiveness", "🚴"),
        ("The early bird might get the worm, but the second mouse gets the cheese", "🐛"),
        ("I thought I wanted a career, turns out I just wanted paychecks", "💵"),
        ("A bank is a place that will lend you money, if you can prove that you don’t need it", "🏦"),
        ("Laugh at your problems, everybody else does", "🤔"),
        ("I love my job only when I'm on vacation", "🏝"),
        ("Who says nothing is impossible? I've been doing nothing for years", "🤪"),
        ("I always dream of being a millionaire like my uncle!... He's dreaming too", "🤑"),
        ("Don’t try to hard, the best things come when you least expect them to", "👏"),
        ("The quieter you become, the more you can hear", "🧘"),
        ("The dearest one may be a stranger in the next year", "💔"),
        ("Live for what tomorrow has to offer, not for what yesterday took away", ""),
        ("Give every opportunity a chance, leave no room for regrets", "💪"),
        ("Save your heart for someone who cares", "💝"),
        ("Life is like an onion: you peel it off one layer at a time, and sometimes you weep", "🧅"),
        ("Mom said that people should not miss two things, the last bus home car and the person who loves you", "🚌"),
        ("Sometimes, people are crying, not because of weak, but because they strong too long!", "🦧"),
        ("Forget all the reason why it won't work and believe the one reason why it will", "🤔"),
        ("If you don't understand my silence, you will never understand my words", "🙉‍"),
        ("Nobody is perfect. But you are close enough for me", "🥂"),
        ("If you hate me,you're the loser，not me", "🤹"),
        ("There is always someone who loves you, even if you don’t notice", "🤕"),
        ("If you want something, don't wish for it. Life is too short to wait", "⏱️"),
        ("Trust is like a paper. Once it’s crumpled, it can't be perfect", "✂️"),
        ("Love fight, get treasure, Miss forget, life is actually so simple", "🌈"),
        ("When a girl tells you about her problems it does not mean that she complains.She trusts you", "⏳"),
        ("I can't set my hopes too high, 'cause every hello ends with a goodbye", "✋"),
        ("Do not blame your food because you have no appetite", "🥢"),
        ("Sometimes, the hardest things to say are those that come straight from the heart", "💓"),
        ("Each of us comes to this world by traveling alone.Even though we have partners,at last we will go different way", "👣"),
        ("You were a dream，then a reality, now a memory", "💋"),
        ("Only because many people said it, doesn’t mean it’s true. You don’t always have to follow the crowd", "👀"),
        ("Sometimes friends become enemies. But what's worse is when they become strangers", "🐸"),
        ("It is funny how the people that hurt you the most are the ones who said they never would", "💔"),
        ("Earth provides enough to satisfy every man's need, but not every man's greed", "🌍"),
        ("Life can be wandering, can be lonely, but your soul has to be a refuge", "🏕"),
        ("For every minute you are angry you lose sixty seconds of happiness", "🎏"),
        ("When I was young, happiness was simple; now that I've grown up, simplicity is happiness", ""),
        ("The greatest pleasure in life is doing what people say you cannot do", "🤛"),
        ("Promises are often like the butterfly, which disappear after beautiful hover", "🦋"),
        ("We never really grow up, we just learned to pretend in front of others", "👤"),
        ("Things are always working out when you at least expected it", "👈"),
        ("If you get tired, learn to rest, not to quit", "🤪"),
        ("Nobody looks down on you because everybody is too busy to look at you", "😱"),
        ("Yes, I am nice. No, that doesn't mean you can walk all over me", "😤"),
        ("People will change, memories won't", "🎞"),
        ("Eat a piece of candy every day and tell yourself the day is sweet again", "🍭"),
        ("What would you do if you were not afraid?", "👊"),
        ("My mom said follow your dreams, so I went back to my bed", "💤"),
        ("Seeing a spider in my room isn't scary, it is scary when it disappears", "🕷"),
        ("My goal was to loss 15 pounds this year", "🙀"),
        ("At night I can't fall asleep, I the morning I can't get up", "🙃"),
        ("They say \"don't try this at home\" so I'm coming over to your house to try it", "🧶"),
        ("I know that I am stupid but when I look around me I feel a lot better", "🤝"),
        ("I'm always in a rush to go home, and do absolutely nothing", "🎯"),
        ("If you think your boss is stupid, remember: you wouldn't have a job if he was any smarter", "💯"),
        ("When I wake up at 6 in the morning, I close my eyes for 5 minutes and it's already 6:45", "👍"),
        ("I hate Mondays, Tuesdays, Wednesdays, Thursdays, and half of Fridays", "🥱"),
        ("If you do right, no one remember. If you do wrong, no one forget", "😤"),
        ("You wanna to know whom I'm in love with? Read the first word again", "💘"),

    ];
    let mut rng = rand::thread_rng();
    let jok = joks[rng.gen_range(0, joks.len())];
    format!("{} {}", jok.0, Emoji::new(jok.1, ""))
}
