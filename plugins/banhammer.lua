-- data saved to moderation.json

do

  -- make sure to set with value that not higher than stats.lua
  local NUM_MSG_MAX = 4  -- Max number of messages per TIME_CHECK seconds
  local TIME_CHECK = 4
  local NO_k = 'I will not k myself, sudoers, admins or moderators.'
  local NO_b = 'I will not b myself, sudoers, admins or moderators.'
  local NO_sub = 'I will not sub myself, sudoers, admins or moderators.'

  local function k_user(user_id, chat_id)
    -- check if user was ked in the last TIME_CHECK seconds
    if not redis:get('ked:'..chat_id..':'..user_id) or false then
      if user_id == tostring(our_id) then
        send_large_msg('chat#id'..chat_id, 'I won\'t k myself.')
      else
        chat_del_user('chat#id'..chat_id, 'user#id'..user_id, ok_cb, true)
      end
    end
    -- set for TIME_CHECK seconds that user have been ked
    redis:setex('ked:'..chat_id..':'..user_id, TIME_CHECK, 'true')
  end

  local function b_user(user_id, chat_id)
    -- Save to redis
    redis:set('bned:'..chat_id..':'..user_id, true)
    -- k from chat
    k_user(user_id, chat_id)
  end

  local function sub_user(user_id, chat_id)
    redis:set('subned:'..user_id, true)
    k_user(user_id, chat_id)
  end

  local function unb_user(user_id, chat_id)
    redis:del('bned:'..chat_id..':'..user_id)
  end

  local function suunb_user(user_id, chat_id)
    redis:del('subned:'..user_id)
    return 'User '..user_id..' unbned'
  end

  local function action_by_id(extra, success, result)
    if success == 1 then
      local matches = extra.matches
      local chat_id = result.id
      local group_member = false
      for k,v in pairs(result.members) do
        if matches[2] == tostring(v.id) then
          group_member = true
          local full_name = (v.first_name or '')..' '..(v.last_name or '')
          if matches[1] == 'b' then
            if is_mod(matches[2], chat_id) then
              send_large_msg('chat#id'..chat_id, NO_b)
            else
              b_user(matches[2], chat_id)
              send_large_msg('chat#id'..chat_id, full_name..' ['..matches[2]..'] bned')
            end
          elseif matches[1] == 'sub' then
            if is_mod(matches[2], chat_id) then
              send_large_msg('chat#id'..chat_id, NO_sub)
            else
              sub_user(matches[2], chat_id)
              send_large_msg('chat#id'..chat_id, full_name..' ['..matches[2]..'] globally bned.')
            end
          elseif matches[1] == 'k' then
            if is_mod(matches[2], chat_id) then
              send_large_msg('chat#id'..chat_id, NO_k)
            else
              k_user(matches[2], chat_id)
            end
          end
        end
      end
      if matches[1] == 'unb' then
        if is_bned(matches[2], chat_id) then
          unb_user(matches[2], chat_id)
          send_large_msg('chat#id'..chat_id, 'User with ID ['..matches[2]..'] is unbned.')
        else
          send_large_msg('chat#id'..chat_id, 'No user with ID '..matches[2]..' in (su)b list.')
        end
      elseif matches[1] == 'suunb' then
        if is_su_bned(matches[2]) then
          suunb_user(matches[2], chat_id)
          send_large_msg('chat#id'..chat_id, 'User with ID ['..matches[2]..'] is globally unbned.')
        else
          send_large_msg('chat#id'..chat_id, 'No user with ID '..matches[2]..' in (su)b list.')
        end
      end
      if not group_member then
        send_large_msg('chat#id'..chat_id, 'No user with ID '..matches[2]..' in this group.')
      end
    end
  end

  local function action_by_reply(extra, success, result)
    local chat_id = result.to.id
    local user_id = result.from.id
    local full_name = (result.from.first_name or '')..' '..(result.from.last_name or '')
    if is_chat_msg(result) then
      if extra.match == 'k' then
        if is_mod(user_id, chat_id) then
          send_large_msg('chat#id'..chat_id, NO_k)
        else
          k_user(user_id, chat_id)
        end
      elseif extra.match == 'b' then
        if is_mod(user_id, chat_id) then
          send_large_msg('chat#id'..chat_id, NO_b)
        else
          b_user(user_id, chat_id)
        end
      elseif extra.match == 'sub' then
        if is_mod(user_id, chat_id) then
          send_large_msg('chat#id'..chat_id, NO_sub)
        else
          sub_user(user_id, chat_id)
          send_large_msg('chat#id'..chat_id, full_name..' ['..user_id..'] globally bned.')
        end
      elseif extra.match == 'unb' then
        unb_user(user_id, chat_id)
        send_large_msg('chat#id'..chat_id, 'User '..user_id..' unbned')
      elseif extra.match == 'suunb' then
        suunb_user(user_id, chat_id)
        send_large_msg('chat#id'..chat_id, full_name..' ['..user_id..'] globally unbned.')
      elseif extra.match == 'whitelist' then
        redis:set('whitelist:user#id'..user_id, true)
        send_large_msg('chat#id'..chat_id, full_name..' ['..user_id..'] whitelisted')
      elseif extra.match == 'unwhitelist' then
        redis:del('whitelist:user#id'..user_id)
        send_large_msg('chat#id'..chat_id, full_name..' ['..user_id..'] removed from whitelist')
      end
    else
      return 'Use This in Your Groups'
    end
  end

  local function resolve_username(extra, success, result)
    local chat_id = extra.msg.to.id
    if result ~= false then
      local user_id = result.id
      local username = result.username
      if is_chat_msg(extra.msg) then
        if extra.match == 'k' then
          if is_mod(user_id, chat_id) then
            send_large_msg('chat#id'..chat_id, NO_k)
          else
            k_user(user_id, chat_id)
          end
        elseif extra.match == 'b' then
          if is_mod(user_id, chat_id) then
            send_large_msg('chat#id'..chat_id, NO_b)
          else
            b_user(user_id, chat_id)
            send_large_msg('chat#id'..chat_id, 'User @'..username..' bned')
          end
        elseif extra.match == 'sub' then
          if is_mod(user_id, chat_id) then
            send_large_msg('chat#id'..chat_id, NO_sub)
          else
            sub_user(user_id, chat_id)
            send_large_msg('chat#id'..chat_id, 'User @'..username..' ['..user_id..'] globally bned.')
          end
        elseif extra.match == 'unb' then
          unb_user(user_id, chat_id)
          send_large_msg('chat#id'..chat_id, 'User @'..username..' unbned', ok_cb,  true)
        elseif extra.match == 'suunb' then
          suunb_user(user_id, chat_id)
          send_large_msg('chat#id'..chat_id, 'User @'..username..' ['..user_id..'] globally unbned.')
        end
      else
        return 'Use This in Your Groups.'
      end
    else
      send_large_msg('chat#id'..chat_id, 'No user '..string.gsub(extra.msg.text, '^.- ', '')..' in this group.')
    end
  end

  local function trigger_anti_splooder(user_id, chat_id, splooder)
    local data = load_data(_config.moderation.data)
    local anti_spam_stat = data[tostring(chat_id)]['settings']['anti_flood']
    if anti_spam_stat == 'k' then
      k_user(user_id, chat_id)
      send_large_msg('chat#id'..chat_id, 'User '..user_id..' is '..splooder)
    elseif anti_spam_stat == 'b' then
      b_user(user_id, chat_id)
      send_large_msg('chat#id'..chat_id, 'User '..user_id..' is '..splooder..'. bned')
    end
    msg = nil
  end

  local function pre_process(msg)

    local user_id = msg.from.id
    local chat_id = msg.to.id

    -- ANTI SPAM
    if msg.from.type == 'user' and msg.text and not is_mod(user_id, chat_id) then
      local _nl, ctrl_chars = string.gsub(msg.text, '%c', '')
      -- if string length more than 2048 or control characters is more than 50
      if string.len(msg.text) > 2048 or ctrl_chars > 50 then
        local _c, chars = string.gsub(msg.text, '%a', '')
        local _nc, non_chars = string.gsub(msg.text, '%A', '')
        -- if non characters is bigger than characters
        if non_chars > chars then
          local splooder = 'spamming'
          trigger_anti_splooder(user_id, chat_id, splooder)
        end
      end
    end

    -- ANTI FLOOD
    local post_count = 'floodc:'..user_id..':'..chat_id
    redis:incr(post_count)
    if msg.from.type == 'user' and not is_mod(user_id, chat_id) then
      local post_count = 'user:'..user_id..':floodc'
      local msgs = tonumber(redis:get(post_count) or 0)
      if msgs > NUM_MSG_MAX then
        local splooder = 'flooding'
        trigger_anti_splooder(user_id, chat_id, splooder)
      end
      redis:setex(post_count, TIME_CHECK, msgs+1)
    end

    -- SERVICE MESSAGE
    if msg.action and msg.action.type then
      local action = msg.action.type
      -- Check if bned user joins chat
      if action == 'chat_add_user' or action == 'chat_add_user_link' then
        if msg.action.link_issuer then
          user_id = msg.from.id
        else
	        user_id = msg.action.user.id
        end
        print('>>> bhammer : Checking invited user '..user_id)
        if is_su_bned(user_id) or is_bned(user_id, chat_id) then
          print('>>> bhammer : '..user_id..' is (su)bned from '..chat_id)
          k_user(user_id, chat_id)
        end
      end
      -- No further checks
      return msg
    end

    -- bNED USER TALKING
    if is_chat_msg(msg) then
      if is_su_bned(user_id) then
        print('>>> bhammer : subned user talking.')
        sub_user(user_id, chat_id)
        msg.text = ''
      elseif is_bned(user_id, chat_id) then
        print('>>> bhammer : bned user talking.')
        b_user(user_id, chat_id)
        msg.text = ''
      end
    end

    -- WHITELIST
    -- Allow all sudo users even if whitelist is allowed
    if redis:get('whitelist:enabled') and not is_sudo(user_id) then
      print('>>> bhammer : Whitelist enabled and not sudo')
      -- Check if user or chat is whitelisted
      local allowed = redis:get('whitelist:user#id'..user_id) or false
      if not allowed then
        print('>>> bhammer : User '..user_id..' not whitelisted')
        if is_chat_msg(msg) then
          allowed = redis:get('whitelist:chat#id'..chat_id) or false
          if not allowed then
            print ('Chat '..chat_id..' not whitelisted')
          else
            print ('Chat '..chat_id..' whitelisted :)')
          end
        end
      else
        print('>>> bhammer : User '..user_id..' allowed :)')
      end

      if not allowed then
        msg.text = ''
      end

    else
      print('>>> bhammer : Whitelist not enabled or is sudo')
    end

    return msg
  end

  local function run(msg, matches)

    local user = 'user#id'..(matches[2] or '')

    if is_chat_msg(msg) then
      if matches[1] == 'kme' then
        if is_mod(msg.from.id, msg.to.id) then
          send_large_msg('chat#id'..msg.to.id, NO_k)
        else
          k_user(msg.from.id, msg.to.id)
        end
      end
      if is_mod(msg.from.id, msg.to.id) then
        if matches[1] == 'k' then
          if msg.reply_id then
            msgr = get_message(msg.reply_id, action_by_reply, {msg=msg, match=matches[1]})
          elseif string.match(matches[2], '^%d+$') then
            chat_info('chat#id'..msg.to.id, action_by_id, {msg=msg, matches=matches})
          elseif string.match(matches[2], '^@.+$') then
            msgr = res_user(string.gsub(matches[2], '@', ''), resolve_username, {msg=msg, match=matches[1]})
          end
        elseif matches[1] == 'b' then
          if msg.reply_id then
            msgr = get_message(msg.reply_id, action_by_reply, {msg=msg, match=matches[1]})
          elseif string.match(matches[2], '^%d+$') then
            chat_info('chat#id'..msg.to.id, action_by_id, {msg=msg, matches=matches})
          elseif string.match(matches[2], '^@.+$') then
            msgr = res_user(string.gsub(matches[2], '@', ''), resolve_username, {msg=msg, match=matches[1]})
          end
        elseif matches[1] == 'blist' then
          local text = 'b list for '..msg.to.title..' ['..msg.to.id..']:\n\n'
          for k,v in pairs(redis:keys('bned:'..msg.to.id..':*')) do
            text = text..k..'. '..v..'\n'
          end
          return string.gsub(text, 'bned:'..msg.to.id..':', '')
        elseif matches[1] == 'unb' then
          if msg.reply_id then
            msgr = get_message(msg.reply_id, action_by_reply, {msg=msg, match=matches[1]})
          elseif string.match(matches[2], '^%d+$') then
            chat_info('chat#id'..msg.to.id, action_by_id, {msg=msg, matches=matches})
          elseif string.match(matches[2], '^@.+$') then
            msgr = res_user(string.gsub(matches[2], '@', ''), resolve_username, {msg=msg, match=matches[1]})
          end
        end
        if matches[1] == 'as' then
          local data = load_data(_config.moderation.data)
          local settings = data[tostring(msg.to.id)]['settings']
          if matches[2] == 'k' then
            if settings.anti_flood ~= 'k' then
              settings.anti_flood = 'k'
              save_data(_config.moderation.data, data)
            end
              return 'Anti flood and spam protection already enabled.\nOffender will be ked.'
            end
          if matches[2] == 'b' then
            if settings.anti_flood ~= 'b' then
              settings.anti_flood = 'b'
              save_data(_config.moderation.data, data)
            end
              return 'Anti flood and spam protection already enabled.\nOffender will be bned.'
            end
          if matches[2] == 'disable' then
            if settings.anti_flood == 'no' then
              return 'Anti flood and spam protection is not enabled.'
            else
              settings.anti_flood = 'no'
              save_data(_config.moderation.data, data)
              return 'Anti flood and spam protection has been disabled.'
            end
          end
        end
        if matches[1] == 'whitelist' then
          if msg.reply_id then
            msgr = get_message(msg.reply_id, action_by_reply, {msg=msg, match=matches[1]})
          end
          if matches[2] == 'enable' then
            redis:set('whitelist:enabled', true)
            return 'Enabled whitelist'
          elseif matches[2] == 'disable' then
            redis:del('whitelist:enabled')
            return 'Disabled whitelist'
          elseif matches[2] == 'user' then
            redis:set('whitelist:user#id'..matches[3], true)
            return 'User '..matches[3]..' whitelisted'
          elseif matches[2] == 'delete' and matches[3] == 'user' then
            redis:del('whitelist:user#id'..matches[4])
            return 'User '..matches[4]..' removed from whitelist'
          elseif matches[2] == 'chat' then
            redis:set('whitelist:chat#id'..msg.to.id, true)
            return 'Chat '..msg.to.id..' whitelisted'
          elseif matches[2] == 'delete' and matches[3] == 'chat' then
            redis:del('whitelist:chat#id'..msg.to.id)
            return 'Chat '..msg.to.id..' removed from whitelist'
          end
        elseif matches[1] == 'unwhitelist' and msg.reply_id then
          msgr = get_message(msg.reply_id, action_by_reply, {msg=msg, match=matches[1]})
        end
      end
      if is_admin(msg.from.id, msg.to.id) then
        if matches[1] == 'sub' then
          if msg.reply_id then
            msgr = get_message(msg.reply_id, action_by_reply, {msg=msg, match=matches[1]})
          elseif string.match(matches[2], '^%d+$') then
            chat_info('chat#id'..msg.to.id, action_by_id, {msg=msg, matches=matches})
          elseif string.match(matches[2], '^@.+$') then
            msgr = res_user(string.gsub(matches[2], '@', ''), resolve_username, {msg=msg, match=matches[1]})
          end
        elseif matches[1] == 'suunb' then
          if msg.reply_id then
            msgr = get_message(msg.reply_id, action_by_reply, {msg=msg, match=matches[1]})
          elseif string.match(matches[2], '^%d+$') then
            chat_info('chat#id'..msg.to.id, action_by_id, {msg=msg, matches=matches})
          elseif string.match(matches[2], '^@.+$') then
            msgr = res_user(string.gsub(matches[2], '@', ''), resolve_username, {msg=msg, match=matches[1]})
          end
        end
      end
    else
      print '>>> This is not a chat group.'
    end
  end

  return {
    description = 'Plugin to manage bs, ks and white/black lists.',
    usage = {
      user = {
        '.kme : k yourself out of this group.'
      },
      admin = {
        '.sub : If type in reply, will b user globally.',
        '.sub <user_id>/@<username> : k user_id/username from all chat and ks it if joins again',
        '.suunb : If type in reply, will unb user globally.',
        '.suunb <user_id>/@<username> : Unb user_id/username globally.'
      },
      moderator = {
        '.as k : Enable flood and spam protection. Offender will be ked.',
        '.as b : Enable flood and spam protection. Offender will be bned.',
        '.as disable : Disable flood and spam protection',
        '.b : If type in reply, will b user from chat group.',
        '.b <user_id>/<@username>: k user from chat and ks it if joins chat again',
        '.blist : List users bned from chat group.',
        '.unb : If type in reply, will unb user from chat group.',
        '.unb <user_id>/<@username>: Unb user',
        '.k : If type in reply, will k user from chat group.',
        '.k <user_id>/<@username>: k user from chat group',
        '.whitelist : If type in reply, allow user to use the bot when whitelist mode is enabled',
        '.whitelist chat: Allow everybody on current chat to use the bot when whitelist mode is enabled',
        '.whitelist delete chat: Remove chat from whitelist',
        '.whitelist delete user <user_id>: Remove user from whitelist',
        '.whitelist <enable>/<disable>: Enable or disable whitelist mode',
        '.whitelist user <user_id>: Allow user to use the bot when whitelist mode is enabled',
        '.unwhitelist : If type in reply, remove user from whitelist'
      },
    },
    patterns = {
      '^.(as) (.*)$',
      '^.(b) (.*)$',
      '^.(b)$',
      '^.(blist)$',
      '^.(unb) (.*)$',
      '^.(unb)$',
      '^.(k) (.+)$',
      '^.(k)$',
      '^.(kme)$',
      '^..tgservice (.+)$',
      '^.(whitelist)$',
      '^.(whitelist) (chat)$',
      '^.(whitelist) (delete) (chat)$',
      '^.(whitelist) (delete) (user) (%d+)$',
      '^.(whitelist) (disable)$',
      '^.(whitelist) (enable)$',
      '^.(whitelist) (user) (%d+)$',
      '^.(unwhitelist)$',
      '^.(sub)$',
      '^.(sub) (.*)$',
      '^.(suunb)$',
      '^.(suunb) (.*)$'
    },
    run = run,
    pre_process = pre_process
  }

end
