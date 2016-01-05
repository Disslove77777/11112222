-- data saved to moderation.json

do

  -- make sure to set with value that not higher than stats.lua
  local NUM_MSG_MAX = 4  -- Max number of messages per TIME_CHECK seconds
  local TIME_CHECK = 4
  
  local NO_k = 'I will not k myself, sudoers, admins or moderators!'
  local NO_b = 'I will not b myself, sudoers, admins or moderators!'
  local NO_SUPERb = 'I will not superb myself, sudoers, admins or moderators!'

  local function is_user_whitelisted(id)
    return redis:get('whitelist:user#id'..id) or false
  end

  local function is_chat_whitelisted(id)
    return redis:get('whitelist:chat#id'..id) or false
  end

  local function k_user(user_id, chat_id)
    if user_id == tostring(our_id) then
      send_msg('chat#id'..chat_id, "I won't k myself.", ok_cb,  true)
    else
      chat_del_user('chat#id'..chat_id, 'user#id'..user_id, ok_cb, true)
    end
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

  local function is_su_bned(user_id)
      return redis:get('subned:'..user_id) or false
  end

  local function unb_user(user_id, chat_id)
    redis:del('bned:'..chat_id..':'..user_id)
  end

  local function suunb_user(user_id, chat_id)
    redis:del('subned:'..user_id)
    return 'User '..user_id..' unbned'
  end

  local function is_bned(user_id, chat_id)
    return redis:get('bned:'..chat_id..':'..user_id) or false
  end

  local function action_by_id(extra, success, result)
    if success == 1 then
      local matches = extra.matches
      local chat_id = result.id
      local receiver = 'chat#id'..chat_id
      local group_member = false
      for k,v in pairs(result.members) do
        if matches[2] == tostring(v.id) then
          group_member = true
          local full_name = (v.first_name or '')..' '..(v.last_name or '')
          if matches[1] == 'b' then
            b_user(matches[2], chat_id)
            send_large_msg(receiver, full_name..' ['..matches[2]..'] bned', ok_cb,  true)
          elseif matches[1] == 'sub' then
            sub_user(matches[2], chat_id)
            send_large_msg(receiver, full_name..' ['..matches[2]..'] globally bned.', ok_cb, true)
          elseif matches[1] == 'k' then
            k_user(matches[2], chat_id)
          end
        end
      end
      if matches[1] == 'unb' then
        if is_bned(matches[2], chat_id) then
          unb_user(matches[2], chat_id)
          send_large_msg(receiver, 'User with ID ['..matches[2]..'] is unbned.')
        else
          send_large_msg(receiver, 'No user with ID '..matches[2]..' in (su)b list.')
        end
      elseif matches[1] == 'suunb' then
        if is_su_bned(matches[2]) then
          suunb_user(matches[2], chat_id)
          send_large_msg(receiver, 'User with ID ['..matches[2]..'] is globally unbned.')
        else
          send_large_msg(receiver, 'No user with ID '..matches[2]..' in (su)b list.')
        end
      end
      if not group_member then
        send_large_msg(receiver, 'No user with ID '..matches[2]..' in this group.')
      end
    end
  end

  local function action_by_reply(extra, success, result)
    local msg = result
    local receiver = get_receiver(msg)
    local chat_id = msg.to.id
    local user_id = msg.from.id
    local user = 'user#id'..msg.from.id
    local full_name = (msg.from.first_name or '')..' '..(msg.from.last_name or '')
    if is_chat_msg(msg) and not is_sudo(msg) then
      if extra.match == 'k' then
        chat_del_user(receiver, user, ok_cb, false)
      elseif extra.match == 'b' then
        b_user(user_id, chat_id)
        send_msg(receiver, 'User '..user_id..' bned', ok_cb,  true)
      elseif extra.match == 'sub' then
        sub_user(user_id, chat_id)
        send_large_msg(receiver, full_name..' ['..user_id..'] globally bned.')
      elseif extra.match == 'unb' then
        unb_user(user_id, chat_id)
        send_msg(receiver, 'User '..user_id..' unbned', ok_cb,  true)
      elseif extra.match == 'suunb' then
        suunb_user(user_id, chat_id)
        send_large_msg(receiver, full_name..' ['..user_id..'] globally unbned.')
      end
    else
      return 'Use This in Your Groups'
    end
  end

  local function resolve_username(extra, success, result)
    local msg = extra.msg
    local receiver = get_receiver(msg)
    local chat_id = msg.to.id
    if result ~= false then
      local user_id = result.id
      local user = 'user#id'..result.id
      local username = result.username
      if is_chat_msg(msg) then
        -- check if sudo users
        local is_sudoers = false
        for v,sudoer in pairs(_config.sudo_users) do
          if sudoer == user_id then
            is_sudoers = true
          end
        end
        if not is_sudoers then
          if extra.match == 'k' then
            chat_del_user(receiver, user, ok_cb, false)
          elseif extra.match == 'b' then
            b_user(user_id, chat_id)
            send_msg(receiver, 'User @'..username..' bned', ok_cb,  true)
          elseif extra.match == 'sub' then
            sub_user(user_id, chat_id)
            send_msg(receiver, 'User @'..username..' ['..user_id..'] globally bned.', ok_cb,  true)
          elseif extra.match == 'unb' then
            unb_user(user_id, chat_id)
            send_msg(receiver, 'User @'..username..' unbned', ok_cb,  true)
          elseif extra.match == 'suunb' then
            suunb_user(user_id, chat_id)
            send_msg(receiver, 'User @'..username..' ['..user_id..'] globally unbned.', ok_cb,  true)
          end
        end
      else
        return 'Use This in Your Groups.'
      end
    else
      send_large_msg(receiver, 'No user @'..extra.user..' in this group.')
    end
  end

  local function pre_process(msg)

    local user_id = msg.from.id
    local chat_id = msg.to.id
    local receiver = get_receiver(msg)
    local user = 'user#id'..user_id

    -- ANTI FLOOD
    local post_count = 'floodc:'..user_id..':'..chat_id
    redis:incr(post_count)
    if msg.from.type == 'user' then
      local post_count = 'user:'..user_id..':floodc'
      local msgs = tonumber(redis:get(post_count) or 0)
      local text = 'User '..user_id..' is flooding'
      if msgs > NUM_MSG_MAX and not is_sudo(msg) then
        local data = load_data(_config.moderation.data)
        local anti_flood_stat = data[tostring(chat_id)]['settings']['anti_flood']
        if anti_flood_stat == 'k' then
          send_large_msg(receiver, text)
          k_user(user_id, chat_id)
          msg = nil
        elseif anti_flood_stat == 'b' then
          send_large_msg(receiver, text)
          b_user(user_id, chat_id)
          send_msg(receiver, 'User '..user_id..' bned', ok_cb,  true)
          msg = nil
        end
      end
      redis:setex(post_count, TIME_CHECK, msgs+1)
    end

    -- SERVICE MESSAGE
    if msg.action and msg.action.type then
      local action = msg.action.type
      -- Check if bned user joins chat
      if action == 'chat_add_user' or action == 'chat_add_user_link' then
        local user_id
        if msg.action.link_issuer then
          user_id = msg.from.id
        else
	        user_id = msg.action.user.id
        end
        print('Checking invited user '..user_id)
        if is_su_bned(user_id) or is_bned(user_id, chat_id) then
          print('User is bned.')
          k_user(user_id, chat_id)
        end
      end
      -- No further checks
      return msg
    end

    -- bNED USER TALKING
    if is_chat_msg(msg) then
      if is_su_bned(user_id) then
        print('subned user talking.')
        sub_user(user_id, chat_id)
        msg.text = ''
      end
      if is_bned(user_id, chat_id) then
        print('bned user talking.')
        b_user(user_id, chat_id)
        msg.text = ''
      end
    end

    -- WHITELIST
    -- Allow all sudo users even if whitelist is allowed
    if redis:get('whitelist:enabled') and not is_sudo(msg) then
      print('Whitelist enabled and not sudo')
      -- Check if user or chat is whitelisted
      if not is_user_whitelisted(user_id) then
        print('User '..user..' not whitelisted')
        if is_chat_msg(msg) then
          if not is_chat_whitelisted(chat_id) then
            print ('Chat '..chat_id..' not whitelisted')
          else
            print ('Chat '..chat_id..' whitelisted :)')
          end
        end
      else
        print('User '..user_id..' allowed :)')
      end

      if not is_user_whitelisted(user_id) then
        msg.text = ''
      end

    else
      print('Whitelist not enabled or is sudo')
    end

    return msg
  end

  local function run(msg, matches)

    vardump(msg)

    local receiver = get_receiver(msg)
    local user = 'user#id'..(matches[2] or '')

    if is_chat_msg(msg) then
      if matches[1] == 'kme' then
        if is_sudo(msg) or is_admin(msg) then
          return "I won't k an admin."
        elseif is_mod(msg) then
          return "I won't k a moderator."
        else
          k_user(msg.from.id, msg.to.id)
        end
      end
      if is_mod(msg) then
        if matches[1] == 'k' then
          if msg.reply_id then
            msgr = get_message(msg.reply_id, action_by_reply, {msg=msg, match=matches[1]})
          elseif string.match(matches[2], '^%d+$') then
            chat_info(receiver, action_by_id, {msg=msg, matches=matches})
          elseif string.match(matches[2], '^@.+$') then
            msgr = res_user(string.gsub(matches[2], '@', ''), resolve_username, {msg=msg, match=matches[1]})
          end
        elseif matches[1] == 'b' then
          if msg.reply_id then
            msgr = get_message(msg.reply_id, action_by_reply, {msg=msg, match=matches[1]})
          elseif string.match(matches[2], '^%d+$') then
            chat_info(receiver, action_by_id, {msg=msg, matches=matches})
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
            chat_info(receiver, action_by_id, {msg=msg, matches=matches})
          elseif string.match(matches[2], '^@.+$') then
            msgr = res_user(string.gsub(matches[2], '@', ''), resolve_username, {msg=msg, match=matches[1]})
          end
        end
        if matches[1] == 'an' then
          local data = load_data(_config.moderation.data)
          local settings = data[tostring(msg.to.id)]['settings']
          if matches[2] == 'k' then
            if settings.anti_flood ~= 'k' then
              settings.anti_flood = 'k'
              save_data(_config.moderation.data, data)
            end
              return 'Anti flood protection already enabled.\nFlooder will be ked.'
            end
          if matches[2] == 'b' then
            if settings.anti_flood ~= 'b' then
              settings.anti_flood = 'b'
              save_data(_config.moderation.data, data)
            end
              return 'Anti flood  protection already enabled.\nFlooder will be bned.'
            end
          if matches[2] == 'disable' then
            if settings.anti_flood == 'no' then
              return 'Anti flood  protection is not enabled.'
            else
              settings.anti_flood = 'no'
              save_data(_config.moderation.data, data)
              return 'Anti flood  protection has been disabled.'
            end
          end
        end
        if matches[1] == 'whitelist' then
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
        end
      end
      if is_admin(msg) then
        if matches[1] == 'sub' then
          if msg.reply_id then
            msgr = get_message(msg.reply_id, action_by_reply, {msg=msg, match=matches[1]})
          elseif string.match(matches[2], '^%d+$') then
            chat_info(receiver, action_by_id, {msg=msg, matches=matches})
          elseif string.match(matches[2], '^@.+$') then
            msgr = res_user(string.gsub(matches[2], '@', ''), resolve_username, {msg=msg, match=matches[1]})
          end
        elseif matches[1] == 'suunb' then
          if msg.reply_id then
            msgr = get_message(msg.reply_id, action_by_reply, {msg=msg, match=matches[1]})
          elseif string.match(matches[2], '^%d+$') then
            chat_info(receiver, action_by_id, {msg=msg, matches=matches})
          elseif string.match(matches[2], '^@.+$') then
            msgr = res_user(string.gsub(matches[2], '@', ''), resolve_username, {msg=msg, match=matches[1]})
          end
        end
      end
    else
      return 'This is not a chat group.'
    end
  end

  return {
    description = "Plugin to manage bs, ks and white/black lists.",
    usage = {
      user = {
        ".kme : k yourself out of this group."
      },
      admin = {
        ".sub : If type in reply, will b user globally.",
        ".sub <user_id>/@<username> : k user_id/username from all chat and ks it if joins again",
        ".suunb : If type in reply, will unb user globally.",
        ".suunb <user_id>/@<username> : Unb user_id/username globally."
      },
      moderator = {
        ".an k : Enable flood protection. Flooder will be ked.",
        ".an b : Enable flood protection. Flooder will be bned.",
        ".an disable : Disable flood protection",
        ".b : If type in reply, will b user from chat group.",
        ".b <user_id>/<@username>: k user from chat and ks it if joins chat again",
        ".blist : List users bned from chat group.",
        ".unb : If type in reply, will unb user from chat group.",
        ".unb <user_id>/<@username>: Unb user",
        ".k : If type in reply, will k user from chat group.",
        ".k <user_id>/<@username>: k user from chat group",
        ".whitelist chat: Allow everybody on current chat to use the bot when whitelist mode is enabled",
        ".whitelist delete chat: Remove chat from whitelist",
        ".whitelist delete user <user_id>: Remove user from whitelist",
        ".whitelist <enable>/<disable>: Enable or disable whitelist mode",
        ".whitelist user <user_id>: Allow user to use the bot when whitelist mode is enabled"
      },
    },
    patterns = {
      "^.(an) (.*)$",
      "^.(b) (.*)$",
      "^.(b)$",
      "^.(blist)$",
      "^.(unb) (.*)$",
      "^.(unb)$",
      "^.(k) (.+)$",
      "^.(k)$",
      "^.(kme)$",
      "^..tgservice (.+)$",
      "^.(whitelist) (chat)$",
      "^.(whitelist) (delete) (chat)$",
      "^.(whitelist) (delete) (user) (%d+)$",
      "^.(whitelist) (disable)$",
      "^.(whitelist) (enable)$",
      "^.(whitelist) (user) (%d+)$",
      "^.(sub)$",
      "^.(sub) (.*)$",
      "^.(suunb)$",
      "^.(suunb) (.*)$"
    },
    run = run,
    pre_process = pre_process
  }

end
